import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  lstat,
  symlink,
  rm,
  open,
  chmod,
} from 'node:fs/promises';
import path from 'node:path';
import {
  sanitizeAudit,
  writeDetail,
  readDetail,
  DETAIL_MAX_BYTES,
  extendDetail,
} from './audit-detail.mjs';
import { writeAudit } from './audit-storage.mjs';
import { auditRecord } from './audit.mjs';
import { readAudit, formatRecord, main } from './audit-view.mjs';
import { decodeDecisionResponse } from './structured-classifier.mjs';

const root = await mkdtemp(
  (await import('node:fs')).realpathSync((await import('node:os')).tmpdir()) + '/approval-details-',
);
test.after(() => rm(root, { recursive: true, force: true }));
const day = new Date().toISOString().slice(0, 10);
const config = {
  version: 1,
  mode: 'enforce',
  model: { providerID: 'fixture', id: 'qwen', variant: 'medium' },
  skillRoots: [],
  protectedRoots: [],
  scratchRoot: root + '/scratch',
  auditRoot: root + '/audit',
  timeoutMs: 1000,
  maxRequestChars: 32000,
};
const scope = { directory: root, scratch: root + '/scratch', agent: 'worker', readOnly: false };
const event = () => ({
  sessionID: 'ses_fixture',
  agent: 'worker',
  action: 'shell',
  resources: ['python3 helper.py'],
  effect: 'ask',
  source: { type: 'tool', messageID: 'msg_call', id: 'call_fixture' },
});
const proof = {
  users: [{ id: 'msg_task', text: 'Run local verification for this task.' }],
  delegation: [],
  nativePermissions: {
    projectID: 'project_fixture',
    sessions: [],
    saved: [],
    scoped: [],
    agent: { rules: [] },
  },
};
const allow = {
  effect: 'allow',
  consequence: 'local_execution',
  inScope: true,
  authorization: 'task',
  evidence: null,
  reason: 'Full model explanation. '.repeat(30),
};
const tool = (command) => ({ name: 'shell', input: { command, workdir: root } });

test('audit redaction covers structured credentials and Python, shell, PEM and URL forms', () => {
  const data = {
    apiKey: 'structured-key',
    accessToken: 'structured-access',
    clientSecret: 'structured-client',
    command:
      'python3 - <<\'PY\'\nPASSWORD = """multiline-secret\nsecond-line-secret"""\nheaders = {"Authorization": "Bearer ' +
      'a'.repeat(30) +
      '"}\nPY\n' +
      'curl --password "cli-password" "https://example.org/?api_key=query-password"',
    helper:
      "cfg = {'token': 'dict-secret', 'api_key': 'dict-key'}\n" +
      '-----BEGIN PRIVATE KEY-----\nprivate-key-material\n-----END PRIVATE KEY-----',
    modelDecision: { authorization: 'task', reason: 'No secret data.' },
  };
  const clean = sanitizeAudit(data),
    serialized = JSON.stringify(clean);
  for (const secret of [
    'structured-key',
    'structured-access',
    'structured-client',
    'multiline-secret',
    'second-line-secret',
    'cli-password',
    'query-password',
    'dict-secret',
    'dict-key',
    'private-key-material',
    'a'.repeat(30),
  ])
    assert.ok(!serialized.includes(secret), secret);
  assert.equal(clean.data.modelDecision.authorization, 'task');
  assert.ok(clean.capture.redacted);
  assert.ok(clean.data.command.includes('\n'));
});

test('byte and string caps are explicit, and sanitization precedes truncation', async () => {
  const payload = sanitizeAudit(
    { command: 'x'.repeat(300) + ' API_KEY=must-never-appear', more: 'a'.repeat(1000) },
    { maxChars: 100, maxString: 80 },
  );
  assert.equal(payload.capture.truncated, true);
  assert.equal(payload.capture.redacted, true);
  assert.ok(!JSON.stringify(payload).includes('must-never-appear'));
  const ref = await writeDetail(root, sanitizeAudit({ command: '😀'.repeat(80000) }), day);
  assert.equal(ref.status, 'stored');
  assert.ok(ref.bytes <= DETAIL_MAX_BYTES);
  assert.equal(ref.truncated, true);
});

test('stored details are private, immutable, and hash-verified', async () => {
  const payload = sanitizeAudit({ command: 'cat harmless.txt\n' });
  const a = await writeDetail(root, payload, day),
    b = await writeDetail(root, payload, day);
  assert.equal(a.path, b.path);
  assert.equal((await lstat(path.join(root, a.path))).mode & 0o777, 0o600);
  const loaded = await readDetail(root, a);
  assert.equal(loaded.data.command, 'cat harmless.txt\n');
  await writeFile(path.join(root, a.path), '{"tampered":true}\n');
  await assert.rejects(readDetail(root, a), /hash mismatch/);
});

test('detail references cannot traverse directories or read links', async () => {
  await assert.rejects(readDetail(root, { path: '../outside', sha256: 'a'.repeat(64) }));
  const ref = await writeDetail(root, sanitizeAudit({ command: 'another fixture' }), day);
  const target = path.join(root, ref.path);
  await rm(target);
  await symlink(path.join(root, 'helper.py'), target);
  await assert.rejects(readDetail(root, ref));
});

test('verbose storage failure is visible and does not block the compact audit', async () => {
  const directory = path.join(root, 'bad-detail-root');
  await mkdir(directory, { mode: 0o700 });
  await symlink(root, path.join(directory, 'details'));
  const record = auditRecord({
    event: event(),
    request: { tool: tool('cat harmless') },
    result: { effect: 'allow', code: 'fixture' },
    original: 'ask',
    applied: 'allow',
    mode: 'enforce',
    elapsedMs: 1,
  });
  await writeAudit(directory, record);
  const row = JSON.parse((await readFile(path.join(directory, day + '.jsonl'), 'utf8')).trim());
  assert.equal(row.applied, 'allow');
  assert.equal(row.details.status, 'unavailable');
});

test('daily verbose budget cannot make approval fail', async () => {
  const directory = path.join(root, 'quota');
  await mkdir(directory, { mode: 0o700 });
  await mkdir(path.join(directory, 'details'), { mode: 0o700 });
  await mkdir(path.join(directory, 'details', day), { mode: 0o700 });
  const file = await open(
    path.join(directory, 'details', day, '0'.repeat(64) + '.json'),
    'w',
    0o600,
  );
  await file.truncate(128 * 1024 * 1024);
  await file.close();
  const ref = await writeDetail(directory, sanitizeAudit({ command: 'fixture' }), day);
  assert.equal(ref.status, 'unavailable');
  assert.equal(ref.code, 'detail_daily_budget');
});

test('null completion and tool-call entries remain classified failures with audit evidence', () => {
  for (const choices of [
    [null],
    [{ finish_reason: 'tool_calls', message: { role: 'assistant', tool_calls: [null] } }],
  ]) {
    assert.throws(
      () => decodeDecisionResponse({ choices }),
      (error) =>
        error.approvalCode === 'classifier_response_invalid' &&
        error.auditDiagnostic.choices.length === 1,
    );
  }
});

test('later native replies retain their own outcome and the model recommendation', () => {
  const original = sanitizeAudit({
    decision: { effect: 'allow', reason: 'Model approved.' },
    command: 'TOKEN=hidden-value',
  });
  const next = extendDetail(original, {
    status: 'native_reply',
    nativeApplied: 'deny',
    attempt: 2,
  });
  assert.equal(next.data.decision.effect, 'allow');
  assert.equal(next.data.lifecycle.nativeApplied, 'deny');
  assert.equal(next.capture.redacted, true);
  const final = extendDetail(next, { status: 'closed', nativeApplied: 'deny', attempt: 2 });
  assert.equal(final.data.lifecycle.status, 'closed');
});
