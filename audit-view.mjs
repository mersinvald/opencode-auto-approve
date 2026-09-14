import { open, readdir, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { safeText } from './audit.mjs';
import { readDetail } from './audit-detail.mjs';

export const statusLabel = (status) =>
  ({
    grant_pending: 'APPROVING',
    resolved: 'UNCONFIRMED',
    scoped_grant_created: 'SCOPE SAVED',
    scoped_grant_revoked: 'SCOPE REVOKED',
  })[status] ?? String(status).toUpperCase();

export async function auditRoot(
  policyFile = path.join(os.homedir(), '.config/opencode/approval-policy.json'),
) {
  const policy = JSON.parse(await readFile(policyFile, 'utf8'));
  if (typeof policy.auditRoot !== 'string' || !path.isAbsolute(policy.auditRoot))
    throw Error('Policy has no absolute auditRoot');
  return policy.auditRoot;
}

export function normalizeRecord(record) {
  if (
    ![1, 2, 3].includes(record?.version) ||
    typeof record.time !== 'string' ||
    !['allow', 'ask', 'deny'].includes(record.proposed)
  )
    return null;
  const legacy = record.version === 1;
  const model = record.model && {
    providerID: safeText(record.model.providerID, 100),
    id: safeText(record.model.id, 100),
    variant: safeText(record.model.variant, 40),
  };
  return {
    version: record.version,
    time: safeText(record.time, 40),
    sessionID: safeText(record.sessionID, 160),
    sourceID: safeText(record.sourceID, 160),
    action: safeText(record.action, 100),
    grantID: record.grantID && safeText(record.grantID, 160),
    requestID: record.version === 3 ? safeText(record.requestID, 160) : undefined,
    status: record.version === 3 ? safeText(record.status, 40) : undefined,
    attempt: record.version === 3 && Number.isInteger(record.attempt) ? record.attempt : undefined,
    nextRetryAt: Number.isFinite(record.nextRetryAt) ? record.nextRetryAt : undefined,
    code: safeText(record.code, 100),
    stage: record.stage && safeText(record.stage, 40),
    mode: safeText(record.mode, 20),
    model,
    original: safeText(record.original, 10),
    proposed: record.proposed,
    applied:
      !legacy &&
      ['allow', 'ask', 'deny', ...(record.version === 3 ? ['pending'] : [])].includes(
        record.applied,
      )
        ? record.applied
        : null,
    preview: legacy ? '[preview not stored]' : safeText(record.preview),
    reason: legacy ? '[comment not stored in legacy record]' : safeText(record.reason),
    modelDecision:
      !legacy && ['allow', 'ask'].includes(record.modelDecision?.effect)
        ? { effect: record.modelDecision.effect, reason: safeText(record.modelDecision.reason) }
        : null,
    elapsedMs: Number.isFinite(record.elapsedMs) ? record.elapsedMs : null,
    details: record.details && {
      status: safeText(record.details.status, 40),
      path: safeText(record.details.path, 160),
      sha256: safeText(record.details.sha256, 64),
      code: safeText(record.details.code, 80),
      redacted: record.details.redacted === true,
      truncated: record.details.truncated === true,
    },
  };
}

export async function readAudit(
  root,
  {
    limit = 30,
    decision,
    session,
    modelOnly = false,
    pendingOnly = false,
    requestIDs,
    excludeKeys,
    accept,
    maxFileBytes = 1024 * 1024,
  } = {},
) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 200)
    throw Error('Limit must be between 1 and 200');
  if (decision && !['ask', 'allow', 'deny'].includes(decision)) throw Error('Unknown decision');
  if (!Number.isInteger(maxFileBytes) || maxFileBytes < 1 || maxFileBytes > 10 * 1024 * 1024)
    throw Error('Invalid audit byte limit');
  const requests = requestIDs && new Set(requestIDs);
  let names;
  try {
    names = (await readdir(root))
      .filter((n) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(n))
      .sort()
      .reverse()
      .slice(0, 14);
  } catch (error) {
    if (error.code === 'ENOENT') return { records: [], skipped: 0, limited: false };
    throw error;
  }
  const records = [],
    seen = new Set();
  let skipped = 0,
    limited = false;
  for (const name of names) {
    let file;
    try {
      file = await open(path.join(root, name), constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw error;
    }
    let contents;
    try {
      const stat = await file.stat();
      if (!stat.isFile()) throw Error('Audit entry is not a regular file');
      const size = Math.min(stat.size, maxFileBytes);
      const buffer = Buffer.alloc(size);
      const { bytesRead } = await file.read(buffer, 0, size, stat.size - size);
      contents = buffer.subarray(0, bytesRead).toString('utf8');
      if (size < stat.size) {
        limited = true;
        contents = contents.slice(contents.indexOf('\n') + 1);
      }
    } finally {
      await file.close();
    }
    // Ignore a partially appended last line until the next refresh.
    const lines = contents.split('\n');
    lines.pop();
    for (const line of lines.reverse()) {
      if (!line.trim()) continue;
      let record;
      try {
        record = normalizeRecord(JSON.parse(line));
      } catch {
        /* Skip corrupt or foreign records. */
      }
      if (!record) {
        skipped++;
        continue;
      }
      // Filter only the latest state of each asynchronous permission request.
      if (record.requestID) {
        const key = record.sessionID + ':' + record.requestID;
        if (seen.has(key)) continue;
        seen.add(key);
      }
      // A V1 proposal is not evidence of the final permission result.
      if (requests && !requests.has(record.requestID)) continue;
      if (excludeKeys?.has(record.sessionID + ':' + (record.requestID || record.sourceID)))
        continue;
      if (
        pendingOnly &&
        (record.mode !== 'enforce' ||
          record.action === 'scoped_permission' ||
          !['ask', 'pending'].includes(record.applied) ||
          record.status === 'native_reply')
      )
        continue;
      if (accept && !accept(record)) continue;
      if (decision && record.applied !== decision) continue;
      if (session && record.sessionID !== session) continue;
      if (modelOnly && !record.model) continue;
      records.push(record);
      if (records.length >= limit) return { records: records.reverse(), skipped, limited };
    }
  }
  return { records: records.reverse(), skipped, limited };
}

export function formatRecord(record) {
  const date = new Date(record.time);
  const time = Number.isNaN(date.valueOf()) ? record.time : date.toLocaleString();
  const label =
    record.action === 'scoped_permission'
      ? statusLabel(record.status)
      : record.applied === 'pending'
        ? `${statusLabel(record.status)} → ${record.status === 'resolved' ? 'automatic reply not confirmed' : 'dialog available; background review active'}`
        : record.applied === 'ask'
          ? 'ASK → user approval required'
          : record.applied === 'allow'
            ? 'ALLOW → permission granted'
            : record.applied === 'deny'
              ? 'DENY'
              : `LEGACY → proposed ${record.proposed}, final not stored`;
  const mode = record.mode !== 'enforce' ? ` [${record.mode}, proposed ${record.proposed}]` : '';
  const origin = record.model ? `${record.model.id}/${record.model.variant}` : 'rule/system';
  const sameReason = record.modelDecision?.reason === record.reason;
  const lines = [
    `${time}  ${label}${mode}`,
    `  ${record.action}: ${record.preview}`,
    `  ${sameReason ? `Model (${record.modelDecision.effect})` : 'Reason'}: ${record.reason}`,
  ];
  if (record.modelDecision && !sameReason)
    lines.push(`  Model (${record.modelDecision.effect}): ${record.modelDecision.reason}`);
  else if (!record.modelDecision && record.model && record.version === 2)
    lines.push('  Model: no valid structured decision returned');
  if (record.grantID) lines.push(`  Scoped permission: ${record.grantID}`);
  lines.push(
    `  ${origin} · ${record.code}${record.stage ? ` · stage: ${record.stage}` : ''} · ${record.elapsedMs ?? '?'}ms · ${record.sessionID}`,
  );
  return lines.join('\n');
}

export async function main(argv = process.argv.slice(2)) {
  const options = {},
    args = [...argv];
  let follow = false,
    json = false,
    details = false,
    policy;
  while (args.length) {
    const flag = args.shift();
    if (flag === '--follow') follow = true;
    else if (flag === '--json') json = true;
    else if (flag === '--details') {
      details = true;
      json = true;
    } else if (flag === '--model-only') options.modelOnly = true;
    else if (['--limit', '--decision', '--session', '--policy'].includes(flag)) {
      const value = args.shift();
      if (!value || value.startsWith('--')) throw Error(`Missing value for ${flag}`);
      if (flag === '--policy') policy = value;
      else options[flag.slice(2)] = flag === '--limit' ? Number(value) : value;
    } else if (flag === '--help' || flag === '-h') {
      process.stdout.write(
        'oc-approvals [--follow] [--decision ask|allow|deny] [--model-only]\n' +
          '             [--session ID] [--limit 1..200] [--json|--details] [--policy FILE]\n' +
          'Read local permission review records. V3 includes background states and native replies. It does not show command execution.\n',
      );
      return;
    } else throw Error(`Unknown option: ${flag}`);
  }
  const root = await auditRoot(policy);
  let previous = new Map(),
    first = true,
    stopped = false;
  const stop = () => {
    stopped = true;
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try {
    do {
      const result = await readAudit(root, options);
      const current = new Map();
      for (const record of result.records) {
        const key = JSON.stringify(record),
          occurrence = (current.get(key) ?? 0) + 1;
        current.set(key, occurrence);
        if (first || occurrence > (previous.get(key) ?? 0)) {
          let output = record;
          if (details && record.details?.status === 'stored') {
            try {
              output = { ...record, detail: await readDetail(root, record.details) };
            } catch (error) {
              output = { ...record, detailError: safeText(error.message) };
            }
          }
          process.stdout.write(
            json ? JSON.stringify(output) + '\n' : formatRecord(record) + '\n\n',
          );
        }
      }
      if (first && !json) {
        if (!result.records.length) process.stdout.write('No matching audit records.\n');
        if (result.limited || result.skipped)
          process.stderr.write(
            `Read bounded log tails. Skipped invalid records: ${result.skipped}.\n`,
          );
      }
      previous = current;
      first = false;
      if (follow && !stopped) await new Promise((resolve) => setTimeout(resolve, 1000));
    } while (follow && !stopped);
  } finally {
    process.off('SIGINT', stop);
    process.off('SIGTERM', stop);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Audit: ${safeText(error.message)}\n`);
    process.exitCode = 1;
  });
}
