import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { grant, grantDescriptor } from './grant-rules.mjs';
import { grantSnapshot, ruleSnapshot, savedGrantSnapshot } from './audit-grants.mjs';
import {
  sanitizeAudit,
  writeDetail,
  readDetail,
  detailPayload,
  extendDetail,
} from './audit-detail.mjs';
import { writeAudit } from './audit-storage.mjs';
import { formatDetailedRecord, normalizeRecord, readAudit } from './audit-view.mjs';

const read = grant('files.read', '/fixture/src/file'),
  write = grant('files.write', 'src/file', 'file', {
    space: { repository: 'a'.repeat(64), modifier: 'scratch' },
    repositoryName: 'infra',
    physicalTarget: '/fixture/wt/src/file',
    binding: { root: '/fixture/wt' },
  });
const global = {
  operation: 'files.read',
  target: '/fixture',
  targetType: 'directory',
  mode: 'allow',
  scope: 'global',
  authority: 'config',
  provenance: { source: 'global defaults' },
};
const saved = {
  operation: 'files.write',
  target: 'src',
  targetType: 'directory',
  space: write.space,
  repositoryName: 'infra',
  mode: 'allow',
  scope: 'project',
  authority: 'model',
};
const checked = {
  decision: 'dynamic',
  analysis: {
    complete: false,
    reason: 'unsupported_command',
    grants: [read, write],
    commands: [{ argv: ['python3', 'helper.py'] }],
    unresolved: [{ reason: 'unsupported_command', commandIndex: 0 }],
  },
  resolution: {
    entries: [
      { grant: read, mode: 'allow', rule: global },
      { grant: write, mode: 'dynamic', rule: null },
    ],
  },
};
const row = {
  version: 3,
  time: new Date().toISOString(),
  sessionID: 'ses_fixture',
  requestID: 'per_fixture',
  action: 'shell',
  status: 'allow',
  code: 'model_allow_once',
  preview: 'cat src/file; python3 helper.py',
  reason: 'Authorized local work.',
  proposed: 'allow',
  applied: 'allow',
  original: 'ask',
  mode: 'enforce',
};
const record = (data, extra = {}) => ({
  ...normalizeRecord({ ...row, ...extra }),
  detail: sanitizeAudit(data),
});

test('pretty details show exact atoms, matched scopes and incomplete coverage', () => {
  const text = formatDetailedRecord(record({ grants: grantSnapshot(checked) }));
  assert.match(text, /Analysis: incomplete · 2 atomic grants/);
  assert.match(text, /Always allow · files.read.*\/fixture\/src\/file/);
  assert.match(text, /via config\/global.*global defaults/);
  assert.match(text, /Dynamic · files.write.*infra · scratch · src\/file/);
  assert.match(text, /resolved: \/fixture\/wt\/src\/file/);
  assert.match(text, /unsupported_command · command 1/);
  assert.match(text, /"python3" "helper.py"/);
  assert.match(text, /Rule changes: none \(allow once\)/);
});

test('saved model rules show transaction deltas and effective grant state changes', () => {
  const update = {
    status: 'saved',
    changes: [{ before: null, after: ruleSnapshot(saved) }],
    ...savedGrantSnapshot([read, write], [global], [], [saved]),
  };
  const text = formatDetailedRecord(
    record(
      { grants: grantSnapshot(checked), lifecycle: { ruleUpdate: update } },
      { status: 'scoped_grant_created', code: 'model_rules_saved', action: 'scoped_permission' },
    ),
  );
  assert.match(text, /Rule changes saved:/);
  assert.match(text, /No exact rule → Always allow · model\/project/);
  assert.match(text, /Grant state: Dynamic → Always allow · files.write/);
  assert.doesNotMatch(text, /Grant state: Always allow →/);
});

test('proposed, failed, missing, truncated and unsafe details cannot masquerade as saved rules', () => {
  const data = { grants: grantSnapshot(checked), lifecycle: { result: { remember: [saved] } } };
  assert.match(formatDetailedRecord(record(data)), /Proposed rules \(save not confirmed\)/);
  data.lifecycle.ruleUpdate = { status: 'failed', reason: 'Concurrent rule change' };
  const failed = formatDetailedRecord(record(data));
  assert.match(failed, /NOT SAVED/);
  assert.doesNotMatch(failed, /Rule changes saved:/);
  assert.match(formatDetailedRecord(normalizeRecord(row)), /not stored/);
  assert.match(
    formatDetailedRecord({ ...normalizeRecord(row), detailError: 'hash mismatch' }),
    /hash mismatch/,
  );
  const partial = record({
    grants: {
      complete: false,
      entries: [{ grant: { target: '\x1b[31mevil', space: '[OMITTED]' }, mode: null }],
      unresolved: [],
    },
  });
  partial.detail.capture.truncated = true;
  assert.match(formatDetailedRecord(partial), /Capture truncated/);
  assert.doesNotMatch(formatDetailedRecord(partial), /\x1b/);
});

test('grant summary survives a long helper and legacy analysis remains readable', () => {
  const p = detailPayload({
    event: { sessionID: 'ses_fixture' },
    request: { scripts: ['x'.repeat(250000)] },
    diagnostics: { static: checked },
    result: { effect: 'allow' },
  });
  assert.equal(p.data.grants.entries[1].grant.target, 'src/file');
  assert.equal(p.capture.truncated, true);
  assert.match(
    formatDetailedRecord(record({ diagnostics: { static: checked } })),
    /2 atomic grants/,
  );
});

test('CLI --details expands pretty output, --json includes the full payload, and old saves recover prior analysis', async () => {
  const root = await mkdtemp(realpathSync(os.tmpdir()) + '/audit-cli-details-');
  try {
    const policy = root + '/policy.json',
      audit = root + '/audit';
    await writeFile(policy, JSON.stringify({ auditRoot: audit }));
    const payload = sanitizeAudit({
      grants: grantSnapshot(checked),
      helpers: [{ body: 'raw-only-helper-body' }],
      lifecycle: { result: { remember: [saved] } },
    });
    await writeAudit(audit, { ...row, detailPayload: payload });
    const cli = fileURLToPath(new URL('./audit-view.mjs', import.meta.url));
    const run = (...args) =>
      execFileSync(process.execPath, [cli, '--policy', policy, ...args], { encoding: 'utf8' });
    const pretty = run('--details');
    assert.match(pretty, /Grants at decision/);
    assert.doesNotMatch(pretty, /raw-only-helper-body/);
    const json = JSON.parse(run('--json'));
    assert.equal(json.detail.data.helpers[0].body, 'raw-only-helper-body');
    assert.doesNotMatch(run(), /Grants at decision/);
    assert.match(run('--help'), /--json.*JSON Lines/);
    assert.throws(() => run('--details', '--json'));
    await writeAudit(audit, {
      ...row,
      action: 'scoped_permission',
      code: 'model_rules_saved',
      status: 'scoped_grant_created',
      preview: 'files.write src',
    });
    const latest = await readAudit(audit, { limit: 1, includePriorDetails: true });
    assert.equal(latest.records.length, 1);
    assert.equal(latest.records[0].code, 'model_rules_saved');
    assert.equal(latest.records[0].priorDetails.status, 'stored');
    const legacy = run('--details', '--limit', '1');
    assert.match(legacy, /2 atomic grants/);
    assert.match(legacy, /previous states not recorded/);
    // New save records retain full detail without a historical lookup.
    const ruleUpdate = {
      status: 'saved',
      changes: [{ before: null, after: saved }],
      ...savedGrantSnapshot([read, write], [global], [], [saved]),
    };
    await writeAudit(audit, {
      ...row,
      action: 'scoped_permission',
      code: 'model_rules_saved',
      status: 'scoped_grant_created',
      detailPayload: extendDetail(payload, { ruleUpdate }),
    });
    const newest = run('--details', '--limit', '1');
    assert.match(newest, /Dynamic → Always allow/);
    assert.doesNotMatch(newest, /previous states not recorded/);
    const captured = JSON.parse(run('--json', '--limit', '1'));
    assert.equal(captured.detail.data.lifecycle.ruleUpdate.status, 'saved');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('static approval details show the matched allow state without implying a rule change', () => {
  const snapshot = grantSnapshot({
    ...checked,
    decision: 'allow',
    analysis: { complete: true, grants: [read] },
    resolution: { entries: [{ grant: read, mode: 'allow', rule: global }] },
  });
  const text = formatDetailedRecord(record({ grants: snapshot }, { code: 'grant_rule' }));
  assert.match(text, /Analysis: complete · 1 atomic grant/);
  assert.match(text, /Always allow · files.read/);
  assert.match(text, /via config\/global/);
  assert.doesNotMatch(text, /Rule changes saved/);
});

test('legacy command hashes do not appear as parsed atomic permissions', () => {
  const legacy = structuredClone(checked);
  legacy.resolution.entries.push({
    grant: grant('shell.opaque', 'legacy-command-hash', 'exact'),
    mode: 'allow',
  });
  const text = formatDetailedRecord(record({ diagnostics: { static: legacy } }));
  assert.match(text, /2 atomic grants/);
  assert.doesNotMatch(text, /legacy-command-hash|shell.opaque/);
});
