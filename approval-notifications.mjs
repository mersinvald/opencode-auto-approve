import { constants } from 'node:fs';
import { open, mkdir, lstat, unlink, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { safeText } from './audit.mjs';
import { auditRoot, readAudit } from './audit-view.mjs';

export const WAIT_MS = 5 * 60 * 1000;
const auditKey = (r) => `${r.sessionID}:${r.requestID || r.sourceID}`;
const requestKey = (r) => `${r.sessionID}:${r.id}`;
const unwrap = (value) => {
  if (value?.error) throw Error('Permission status unavailable');
  return value?.data ?? value;
};
const failure = (code) =>
  /fail|invalid|exhaust|unavailable|timeout|not_confirmed|truncated/.test(code ?? '');
const appleScript =
  'on run argv\n display notification (item 2 of argv) with title (item 1 of argv)\nend run';

export async function notifyMac(
  attention,
  options,
  { policyFile, execute = promisify(execFile), platform = process.platform } = {},
) {
  const result = await attention.notify(options);
  if (result.notification || result.skipped || platform !== 'darwin') return result;
  if (policyFile) {
    const cli = JSON.parse(await readFile(path.join(path.dirname(policyFile), 'cli.json'), 'utf8'));
    if (cli.attention?.enabled !== true || cli.attention?.notifications !== true) return result;
  }
  // Some terminals support sound but cannot display OpenTUI notifications.
  // Pass text as arguments to fixed AppleScript. Never execute notification text.
  await execute(
    '/usr/bin/osascript',
    ['-e', appleScript, options.title ?? 'OpenCode', options.message],
    { timeout: 5000, maxBuffer: 2048 },
  );
  return { ok: true, notification: true, sound: result.sound, transport: 'macos' };
}

export function notificationReason(record, now = Date.now()) {
  if (
    record.mode !== 'enforce' ||
    record.action === 'scoped_permission' ||
    record.status === 'native_reply' ||
    record.code === 'pending_gone'
  )
    return null;
  if (record.applied === 'ask' || record.status === 'resolved') {
    return failure(record.code) || record.status === 'resolved'
      ? 'review_failed'
      : 'review_escalated';
  }
  if (record.applied !== 'pending') return null;
  const time = Date.parse(record.time);
  const elapsed = Number.isFinite(record.elapsedMs) && record.elapsedMs >= 0 ? record.elapsedMs : 0;
  return Number.isFinite(time) && now - (time - elapsed) >= WAIT_MS ? 'review_overdue' : null;
}

export function notificationOptions(request, reason) {
  const explanation = {
    review_failed: 'Automatic review failed. Your approval is required.',
    review_escalated: 'Automatic review needs your decision.',
    review_overdue: 'Automatic review has been pending for 5 minutes. You can answer now.',
  }[reason];
  return {
    title: 'OpenCode · Approval pending',
    message: `${safeText(request.action, 50)} · Session …${safeText(request.sessionID, 160).slice(-12)}\n${explanation}\nOpen /approval-audit for details.`,
    notification: { when: 'always' },
    sound: { name: 'permission', when: 'always' },
  };
}

// Exclusive receipts prevent duplicate banners from separate TUI windows and reloads.
// A failed notification releases its receipt. A crash after delivery cannot resend it.
export async function deliverOnce(root, key, send) {
  const directory = path.join(root, 'notifications');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await lstat(directory);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid() ||
    stat.mode & 0o077
  )
    throw Error('Unsafe notification receipt directory');
  const filename = path.join(directory, createHash('sha256').update(key).digest('hex') + '.json');
  let file;
  try {
    file = await open(
      filename,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
  } catch (error) {
    if (error.code === 'EEXIST') return 'duplicate';
    throw error;
  }
  let keep = false;
  try {
    await file.writeFile(
      JSON.stringify({ time: new Date().toISOString(), status: 'attempted' }) + '\n',
    );
    const result = await send();
    keep = result?.notification === true;
    if (keep) {
      await file.truncate(0);
      await file.write(
        JSON.stringify({ time: new Date().toISOString(), status: 'sent' }) + '\n',
        0,
        'utf8',
      );
    }
    return keep ? 'sent' : result == null ? 'cancelled' : 'skipped';
  } finally {
    await file.close();
    if (!keep) await unlink(filename).catch(() => {});
  }
}

export function createApprovalNotifications({
  client,
  policyFile,
  notify,
  onError = () => {},
  now = Date.now,
  records: loadRecords,
  deliver = deliverOnce,
  platform = process.platform,
  intervalMs = 5000,
  schedule = setInterval,
  unschedule = clearInterval,
}) {
  const finished = new Set(),
    inFlight = new Set(),
    retryAt = new Map();
  let stopped = false,
    busy = false,
    timer,
    rootPromise;
  const root = () =>
    (rootPromise ??= auditRoot(policyFile).catch((error) => {
      rootPromise = null;
      throw error;
    }));
  const records =
    loadRecords ??
    (async (options) =>
      (
        await readAudit(await root(), {
          limit: 200,
          maxFileBytes: 10 * 1024 * 1024,
          ...options,
        })
      ).records);
  const pending = async (sessionID) => {
    const list = unwrap(
      await client.permission.list({ sessionID }, { signal: AbortSignal.timeout(5000) }),
    );
    if (!Array.isArray(list)) throw Error('Invalid permission list');
    return list;
  };
  const matches = (r, request) =>
    r.sessionID === request.sessionID &&
    r.action === request.action &&
    (r.requestID ? r.requestID === request.id : r.sourceID && r.sourceID === request.source?.id);
  const remember = (key) => {
    finished.add(key);
    // Receipts still suppress repeats if old in-memory entries are evicted.
    if (finished.size > 10000) finished.delete(finished.values().next().value);
  };
  async function tick() {
    if (stopped || busy || platform !== 'darwin') return;
    busy = true;
    try {
      const rows = await records({
        pendingOnly: true,
        excludeKeys: finished,
        accept: (record) => notificationReason(record, now()) !== null,
      });
      const sessions = new Map();
      for (const record of rows) {
        if (
          !record.sessionID ||
          (!record.requestID && !record.sourceID) ||
          finished.has(auditKey(record))
        )
          continue;
        if (!sessions.has(record.sessionID)) sessions.set(record.sessionID, []);
        sessions.get(record.sessionID).push(record);
      }
      // Small groups bound native API work without serial delays across worker sessions.
      const groups = [...sessions];
      for (let offset = 0; offset < groups.length && !stopped; offset += 8) {
        await Promise.all(
          groups.slice(offset, offset + 8).map(async ([sessionID, group]) => {
            try {
              const requests = await pending(sessionID);
              for (const record of group) {
                if (stopped) return;
                const request = requests.find((r) => matches(record, r));
                if (!request) {
                  remember(auditKey(record));
                  continue;
                }
                const key = requestKey(request);
                if (
                  finished.has(key) ||
                  inFlight.has(key) ||
                  (retryAt.get(key) ?? 0) > now() ||
                  !notificationReason(record, now())
                )
                  continue;
                inFlight.add(key);
                try {
                  // Re-read the latest state after acquiring the receipt, then check the native dialog.
                  const result = await deliver(await root(), key, async () => {
                    const latest = (
                      await records({
                        session: sessionID,
                        ...(record.requestID ? { requestIDs: [request.id] } : {}),
                      })
                    )
                      .filter((r) => matches(r, request))
                      .at(-1);
                    const reason = latest && notificationReason(latest, now());
                    if (!reason || stopped) return null;
                    const current = (await pending(sessionID)).find((r) => r.id === request.id);
                    if (!current || !matches(latest, current) || stopped) return null;
                    return notify(notificationOptions(current, reason));
                  });
                  if (result === 'sent' || result === 'duplicate') {
                    remember(key);
                    retryAt.delete(key);
                  } else if (result === 'skipped') {
                    retryAt.set(key, now() + 60000);
                    onError(
                      'macOS notification was skipped. Check OpenCode attention and macOS notification settings.',
                    );
                  }
                } catch {
                  retryAt.set(key, now() + 60000);
                  onError('Approval notification failed. The approval dialog remains available.');
                } finally {
                  inFlight.delete(key);
                }
              }
            } catch {
              onError(
                'Approval notifications could not check or notify this session. The approval dialog remains available.',
              );
            }
          }),
        );
      }
    } catch {
      onError(
        'Approval notifications could not read the audit. The approval dialog remains available.',
      );
    } finally {
      busy = false;
    }
  }
  return {
    tick,
    start() {
      if (!timer && !stopped && platform === 'darwin') {
        timer = schedule(() => void tick(), intervalMs);
        void tick();
      }
    },
    stop() {
      stopped = true;
      if (timer) unschedule(timer);
    },
  };
}
