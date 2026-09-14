import { vacuumAudit, parseAuditSize } from './audit-maintenance.mjs';
import { terminalLayout } from './audit-terminal.mjs';
import { grantSnapshot } from './audit-grants.mjs';
import { modeLabels } from './grant-rules.mjs';
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
  const maintenance =
    record?.version === 3 &&
    record.kind === 'maintenance' &&
    record.code === 'audit_storage_warning';
  if (
    ![1, 2, 3].includes(record?.version) ||
    typeof record.time !== 'string' ||
    (!maintenance && !['allow', 'ask', 'deny'].includes(record.proposed))
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
    ...(maintenance
      ? {
          kind: 'maintenance',
          storage: {
            bytes: Number(record.storage?.bytes),
            oldestDay: safeText(record.storage?.oldestDay, 10),
            oldestAgeDays: Number(record.storage?.oldestAgeDays),
            thresholds: {
              ageDays: Number(record.storage?.thresholds?.ageDays),
              bytes: Number(record.storage?.thresholds?.bytes),
            },
            triggered: ['age', 'size'].filter((x) => record.storage?.triggered?.includes(x)),
          },
        }
      : {}),
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
    includePriorDetails = false,
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
      .reverse();
  } catch (error) {
    if (error.code === 'ENOENT') return { records: [], skipped: 0, limited: false };
    throw error;
  }
  const records = [],
    seen = new Set(),
    waiting = new Map();
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
        if (seen.has(key)) {
          if (waiting.has(key) && record.details?.status === 'stored') {
            waiting.get(key).priorDetails = record.details;
            waiting.delete(key);
          }
          if (records.length >= limit && !waiting.size)
            return { records: records.reverse(), skipped, limited };
          continue;
        }
        seen.add(key);
      }
      if (records.length >= limit) continue;
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
      if (
        includePriorDetails &&
        record.requestID &&
        record.details?.status !== 'stored' &&
        ['scoped_grant_created', 'scope_not_saved'].includes(record.status)
      )
        waiting.set(record.sessionID + ':' + record.requestID, record);
      if (records.length >= limit && !waiting.size)
        return { records: records.reverse(), skipped, limited };
    }
  }
  return { records: records.reverse(), skipped, limited };
}

export function formatRecord(record, options) {
  if (record.kind === 'maintenance') {
    const ui = terminalLayout(options);
    ui.title('WARNING · audit storage', new Date(record.time).toLocaleString(), 'amber');
    ui.line(record.reason);
    return ui.result();
  }
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
  if (options) {
    const { paint } = terminalLayout(options);
    lines[0] = paint(lines[0], eventTone(record));
    lines[lines.length - 1] = paint(lines.at(-1), 'dim');
  }
  return lines.join('\n');
}

const array = (value) => (Array.isArray(value) ? value : []);
const objects = (value) => array(value).filter((x) => x && typeof x === 'object');
const modeName = (value) =>
  Object.hasOwn(modeLabels, value) ? modeLabels[value] : 'State not recorded';
const shortSession = (id) =>
  safeText(id, 160).length > 16 ? '…' + safeText(id, 160).slice(-12) : safeText(id);
const eventTone = (record) =>
  ({ allow: 'green', deny: 'red', ask: 'amber' })[record.applied] ?? 'cyan';
const grantTone = (mode) => ({ allow: 'green', ask: 'amber', dynamic: 'cyan' })[mode];

export function formatDetailedRecord(record, options) {
  if (record.kind === 'maintenance') return formatRecord(record, options);
  const ui = terminalLayout(options),
    data = record.detail?.data;
  const snapshot = data?.grants ?? grantSnapshot(data?.diagnostics?.static);
  const entries = objects(snapshot?.entries),
    update = data?.lifecycle?.ruleUpdate;
  const aliases = [],
    repositories = new Map();
  const grants = [...entries, ...objects(update?.after)].map((e) => e.grant).filter(Boolean);
  for (const g of [
    ...grants,
    ...objects(update?.changes)
      .map((c) => c.after)
      .filter(Boolean),
  ]) {
    const id = g.space?.repository;
    if (typeof id !== 'string' || repositories.has(id)) continue;
    const base =
      safeText(g.repositoryName ?? id.slice(0, 8), 30).replace(/[^a-zA-Z0-9_.-]/g, '_') ||
      'repository';
    let name = base,
      n = 2;
    while ([...repositories.values()].includes(name)) name = base + '-' + n++;
    repositories.set(id, name);
  }
  for (const g of grants) {
    const root = g?.binding?.root;
    if (typeof root !== 'string' || !path.isAbsolute(root) || aliases.some((a) => a.root === root))
      continue;
    const name =
      safeText(repositories.get(g.space?.repository) ?? g.repositoryName ?? 'worktree', 30).replace(
        /[^a-zA-Z0-9_.-]/g,
        '_',
      ) || 'worktree';
    let alias = '@' + name,
      n = 2;
    while (aliases.some((a) => a.alias === alias)) alias = '@' + name + '-' + n++;
    aliases.push({ root, alias, repository: g.space?.repository });
  }
  const shorten = (value) => {
    let text = safeText(value, 12000);
    for (const a of [...aliases].sort((x, y) => y.root.length - x.root.length)) {
      // Keep sibling paths distinct. This substitution is display-only.
      text = text.replaceAll(a.root + '/', a.alias + '/');
      if (text === a.root) text = a.alias;
    }
    const home = os.homedir();
    return text.replaceAll(home + '/', '~/');
  };
  const target = (g) => {
    if (!g?.target) return '[target not recorded]';
    if (g.space && typeof g.space.repository === 'string') {
      const name =
        repositories.get(g.space.repository) ??
        safeText(g.repositoryName ?? g.space.repository.slice(0, 8), 50);
      return `${name}:scratch/${g.target === '.' ? '' : safeText(g.target, 4000)}${g.targetType === 'directory' && g.target !== '.' ? '/' : ''}`;
    }
    return shorten(g.target) + (g.targetType === 'directory' && !g.target.endsWith('/') ? '/' : '');
  };
  const atom = (g, prefix = '', tone) => {
    ui.line(`${safeText(g?.operation, 160)}  ${target(g)}`, { indent: 4, prefix, tone });
  };
  const via = (r) => {
    if (!r) {
      ui.line('No matching rule', { indent: 6, tone: 'dim' });
      return;
    }
    ui.line(
      `Rule: ${safeText(r.authority ?? 'unknown')}/${safeText(r.scope ?? 'unknown')} · ${safeText(r.operation)} · ${target(r)}`,
      { indent: 6, tone: 'dim' },
    );
  };
  const state = (e) => {
    const label = modeName(e.mode).padEnd(13);
    atom(e.grant, label + '  ', grantTone(e.mode));
    via(e.rule);
    for (const location of objects(e.grant?.locations).slice(0, 3))
      ui.line(
        `Source: ${shorten(location.source)}${Number.isInteger(location.line) ? ':' + location.line : ''}`,
        { indent: 6, tone: 'dim' },
      );
  };
  const date = new Date(record.time),
    stamp = Number.isNaN(date.valueOf())
      ? record.time
      : date.toLocaleString(undefined, {
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
        });
  const event =
    record.action === 'scoped_permission'
      ? statusLabel(record.status)
      : record.applied === 'allow'
        ? 'APPROVED'
        : record.applied === 'ask'
          ? 'APPROVAL NEEDED'
          : record.applied === 'deny'
            ? 'DENIED'
            : record.applied === 'pending'
              ? statusLabel(record.status)
              : 'LEGACY';
  const tone = eventTone(record);
  const duration =
    record.elapsedMs == null
      ? ''
      : record.elapsedMs >= 1000
        ? (record.elapsedMs / 1000).toFixed(1) + ' s'
        : record.elapsedMs + ' ms';
  ui.title(
    `${event} · ${safeText(record.action, 100)}`,
    `${stamp}${duration ? ' · ' + duration : ''}`,
    tone,
  );
  if (record.mode !== 'enforce')
    ui.line(
      `${safeText(record.mode)} · proposed ${record.proposed} · actual ${record.applied ?? 'not recorded'}`,
      { tone: 'amber' },
    );
  if (record.applied === 'pending')
    ui.line(
      record.status === 'resolved'
        ? 'Automatic reply not confirmed'
        : 'Approval dialog available; background review active',
      { tone: 'amber' },
    );
  if (record.applied === null) ui.line('Final outcome not recorded', { tone: 'amber' });
  ui.line(shorten(record.preview), { prefix: record.action === 'shell' ? '$ ' : '' });
  const reason =
    record.modelDecision?.reason === record.reason ? record.modelDecision.reason : record.reason;
  // A static allow is already explained by the per-grant matched rules.
  if (record.code !== 'grant_rule' || record.applied !== 'allow') {
    ui.section(
      record.modelDecision?.reason === record.reason
        ? `MODEL DECISION · ${record.modelDecision.effect}`
        : 'DECISION',
    );
    ui.line(reason);
  }
  if (record.modelDecision && record.modelDecision.reason !== record.reason)
    ui.line(`Model (${record.modelDecision.effect}): ${record.modelDecision.reason}`);
  if (!data) {
    ui.section('GRANTS');
    ui.line(
      'Details unavailable: ' +
        safeText(record.detailError ?? record.details?.code ?? 'not stored for this event'),
      { tone: 'amber' },
    );
  } else if (snapshot) {
    ui.section(
      'GRANTS AT DECISION',
      `${snapshot.complete === true ? 'Complete analysis' : snapshot.complete === false ? 'Incomplete analysis' : 'Coverage not recorded'} · ${entries.length} atomic grant${entries.length === 1 ? '' : 's'}`,
    );
    if (snapshot.restriction) ui.line('Restriction: ' + snapshot.restriction, { tone: 'amber' });
    if (!entries.length) ui.line('No atomic grants identified.', { tone: 'dim' });
    entries.forEach(state);
    if (objects(snapshot.unresolved).length) {
      ui.section('UNRESOLVED', 'These effects require review.');
      for (const u of objects(snapshot.unresolved)) {
        ui.line(
          `${safeText(u.reason ?? snapshot.reason ?? 'not recorded', 600)}${Number.isInteger(u.commandIndex) ? ' · command ' + (u.commandIndex + 1) : ''}`,
          { indent: 4, tone: 'amber' },
        );
        if (u.source)
          ui.line(`Source: ${shorten(u.source)}${Number.isInteger(u.line) ? ':' + u.line : ''}`, {
            indent: 6,
            tone: 'dim',
          });
        if (u.target) ui.line(`Target: ${shorten(u.target)}`, { indent: 6, tone: 'dim' });
        if (u.cwd) ui.line(`Working directory: ${shorten(u.cwd)}`, { indent: 6, tone: 'dim' });
        if (u.cdBranch?.target && ['success', 'failure'].includes(u.cdBranch.outcome))
          ui.line(`After cd ${u.cdBranch.outcome}: ${shorten(u.cdBranch.target)}`, {
            indent: 6,
            tone: 'dim',
          });
        if (u.command?.argv)
          ui.line(
            shorten(
              array(u.command.argv)
                .map((x) => (typeof x === 'string' ? JSON.stringify(x) : '[dynamic value]'))
                .join(' '),
            ),
            { indent: 6, tone: 'dim' },
          );
      }
    }
  } else {
    ui.section('GRANTS');
    ui.line('Grant analysis was not recorded for this event.', { tone: 'dim' });
  }
  if (update?.status === 'saved') {
    ui.section('RULES SAVED', 'Confirmed store changes');
    for (const c of objects(update.changes)) {
      atom(
        c.after,
        `${c.before ? modeName(c.before.mode) : 'No exact rule'} → ${modeName(c.after?.mode)}  `,
        grantTone(c.after?.mode),
      );
      ui.line(`${safeText(c.after?.authority)}/${safeText(c.after?.scope)}`, {
        indent: 6,
        tone: 'dim',
      });
    }
    const before = new Map(objects(update.before).map((e) => [e.grant?.id, e]));
    const changed = objects(update.after).filter((e) => before.get(e.grant?.id)?.mode !== e.mode);
    if (changed.length) {
      ui.section('EFFECT ON GRANTS');
      for (const after of changed)
        atom(
          after.grant,
          `${modeName(before.get(after.grant?.id)?.mode)} → ${modeName(after.mode)}  `,
          grantTone(after.mode),
        );
    }
    if (update.stateError)
      ui.line('State comparison unavailable: ' + update.stateError, { tone: 'amber' });
  } else if (update?.status === 'failed' || record.code === 'rule_save_failed') {
    ui.section('RULES NOT SAVED');
    ui.line(update?.reason ?? record.reason, { tone: 'red' });
  } else {
    const selected = objects(data?.lifecycle?.result?.remember);
    if (record.code === 'model_rules_saved') {
      ui.section('RULES SAVED', 'Legacy event · previous states not recorded');
      selected.forEach((g) => atom(g, 'Always allow  ', 'green'));
      if (!selected.length) ui.line(shorten(record.preview));
    } else if (selected.length) {
      ui.section('PROPOSED RULES', 'Save not confirmed');
      selected.forEach((g) => atom(g, '', 'cyan'));
    } else if (record.code === 'model_allow_once')
      ui.line('Allowed once · no rules changed.', { tone: 'dim' });
  }
  if (aliases.length || repositories.size) {
    ui.section('PATH KEY');
    for (const a of aliases)
      ui.line(`${a.alias} = ${a.root.replace(os.homedir() + '/', '~/')}`, { tone: 'dim' });
    for (const [id, name] of repositories)
      ui.line(
        `${safeText(name ?? id.slice(0, 8))}:scratch = linked worktrees of repository ${safeText(id.slice(0, 8))}`,
        { tone: 'dim' },
      );
  }
  if (record.detail?.capture?.truncated)
    ui.line('Capture truncated: some audit evidence is unavailable.', { tone: 'amber' });
  if (record.detail?.capture?.redacted) ui.line('Sensitive values were redacted.', { tone: 'dim' });
  const origin = record.model ? `${record.model.id}/${record.model.variant}` : 'Static rules';
  ui.line();
  ui.line(
    `${origin} · ${record.code}${record.stage ? ' · ' + record.stage : ''} · session ${shortSession(record.sessionID)}`,
    { tone: 'dim' },
  );
  return ui.result();
}

export async function main(argv = process.argv.slice(2)) {
  const options = {},
    args = [...argv];
  let follow = false,
    json = false,
    details = false,
    color = 'auto',
    policy,
    vacuum = false;
  const cleanup = {};
  while (args.length) {
    const flag = args.shift();
    if (flag === 'vacuum' && !vacuum) vacuum = true;
    else if (flag === '--dry-run') cleanup.dryRun = true;
    else if (flag === '--follow') follow = true;
    else if (flag === '--json') json = true;
    else if (flag === '--details') details = true;
    else if (flag === '--model-only') options.modelOnly = true;
    else if (
      [
        '--limit',
        '--decision',
        '--session',
        '--policy',
        '--color',
        '--keep-days',
        '--max-size',
      ].includes(flag)
    ) {
      const value = args.shift();
      if (!value || value.startsWith('--')) throw Error(`Missing value for ${flag}`);
      if (flag === '--keep-days') cleanup.keepDays = Number(value);
      else if (flag === '--max-size') cleanup.maxBytes = parseAuditSize(value);
      else if (flag === '--color') {
        if (!['auto', 'always', 'never'].includes(value))
          throw Error('Color must be auto, always, or never');
        color = value;
      } else if (flag === '--policy') policy = value;
      else options[flag.slice(2)] = flag === '--limit' ? Number(value) : value;
    } else if (flag === '--help' || flag === '-h') {
      process.stdout.write(
        'oc-approvals [--follow] [--decision ask|allow|deny] [--model-only]\n' +
          '             [--session ID] [--limit 1..200] [--json|--details] [--color auto|always|never] [--policy FILE]\n' +
          'oc-approvals vacuum [--dry-run] [--keep-days 14] [--max-size 1GiB] [--json] [--policy FILE]\n' +
          'vacuum     Remove old UTC audit days. Current-day data and referenced details remain.\n' +
          '--max-size Also remove oldest prior days toward this size, even within --keep-days.\n' +
          '--details  Expand pretty output with analysis, grants, matched rules, and saved changes.\n' +
          '--json     Emit JSON Lines including the stored detail payload.\n' +
          '--color    Default: auto (TTY only; respects NO_COLOR). Use always with less -R.\n' +
          'Read local permission review records. V3 includes background states and native replies. It does not show command execution.\n',
      );
      return;
    } else throw Error(`Unknown option: ${flag}`);
  }
  if (json && details) throw Error('Choose either --json or --details');
  const root = await auditRoot(policy);
  if (vacuum) {
    if (follow || details || Object.keys(options).length)
      throw Error('Vacuum does not accept view filters, --follow, or --details');
    const result = await vacuumAudit(root, cleanup);
    if (json) process.stdout.write(JSON.stringify(result) + '\n');
    else {
      const ui = terminalLayout({ color });
      ui.title(result.dryRun ? 'VACUUM PREVIEW' : 'VACUUM COMPLETE', '', 'cyan');
      ui.line(
        `${result.dryRun ? 'Would remove' : 'Removed'} ${result.files.length} audit files · ${(result.bytesReclaimed / 1024 ** 2).toFixed(2)} MiB`,
      );
      ui.line(
        `Storage: ${(result.bytesBefore / 1024 ** 3).toFixed(2)} → ${(result.bytesAfter / 1024 ** 3).toFixed(2)} GiB`,
      );
      if (result.days.length) ui.line('UTC days: ' + result.days.join(', '));
      if (result.protectedFiles.length)
        ui.line(`${result.protectedFiles.length} detail files retained for newer audit records.`);
      if (!result.targetReached)
        ui.line('Size target not reached: current-day data and referenced details are protected.', {
          tone: 'amber',
        });
      if (result.dryRun)
        ui.line('No files deleted. Run the same command without --dry-run to apply.');
      process.stdout.write(ui.result() + '\n');
    }
    return;
  }
  if (Object.keys(cleanup).length) throw Error('Cleanup options require the vacuum command');
  options.includePriorDetails = details;
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
          const reference =
            record.details?.status === 'stored' ? record.details : record.priorDetails;
          if ((json || details) && reference?.status === 'stored') {
            try {
              output = { ...record, detail: await readDetail(root, reference) };
            } catch (error) {
              output = { ...record, detailError: safeText(error.message) };
            }
          }
          process.stdout.write(
            json
              ? JSON.stringify(output) + '\n'
              : (details
                  ? formatDetailedRecord(output, { color })
                  : formatRecord(record, { color })) + '\n\n',
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
