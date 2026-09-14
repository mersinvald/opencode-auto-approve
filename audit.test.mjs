import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { safeText, requestPreview } from './audit.mjs';
import { readAudit, normalizeRecord, formatRecord } from './audit-view.mjs';

const entry = {
  version: 2,
  time: '2026-09-12T22:00:00Z',
  sessionID: 'ses_test',
  action: 'shell',
  preview: 'npm test',
  proposed: 'allow',
  original: 'ask',
  applied: 'allow',
  mode: 'enforce',
  code: 'model_allow',
  reason: 'Task permits tests.',
  model: { id: 'qwen3.6-35b-a3b', variant: 'medium' },
  modelDecision: { effect: 'allow', reason: 'Task permits tests.' },
};
test('previews redact before truncation and remove terminal or bidi controls', () => {
  assert.ok(!safeText('API_KEY=supersecret \u001b[31m hi\u202ebad').includes('supersecret'));
  assert.ok(!/[\u001b\u202e]/.test(safeText('\u001b\u202e')));
  assert.ok(safeText('x'.repeat(1000)).length <= 400);
  assert.equal(
    requestPreview({ action: 'shell' }, { input: { command: 'python3 -c "private body"' } }),
    'python3 [inline code omitted]',
  );
  assert.equal(
    requestPreview({ action: 'shell' }, { input: { command: 'python3 <<EOF\nprivate body\nEOF' } }),
    'python3 <<EOF [remaining lines omitted]',
  );
  assert.equal(
    requestPreview({ action: 'shell', resources: ['do not copy unknown command'] }),
    '[command unavailable]',
  );
  assert.equal(
    requestPreview(
      { action: 'external_directory', resources: ['/repo/infra/*'] },
      { input: { command: 'python3 lint.py /repo/infra/README.md' } },
    ),
    '/repo/infra/*',
  );
});
test('legacy comments and final outcomes are explicitly unavailable', () => {
  const old = normalizeRecord({ ...entry, version: 1 });
  assert.equal(old.applied, null);
  assert.equal(old.modelDecision, null);
  assert.match(formatRecord(old), /comment not stored/);
  assert.match(formatRecord(old), /final not stored/);
});
test('viewer filters final effects, survives partial lines, and reads rotated logs', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'approval-view-'));
  await writeFile(
    path.join(root, '2026-09-11.jsonl'),
    JSON.stringify({ ...entry, version: 1 }) + '\n',
  );
  await writeFile(
    path.join(root, '2026-09-12.jsonl'),
    [
      JSON.stringify(entry),
      'invalid',
      JSON.stringify({
        ...entry,
        applied: 'ask',
        proposed: 'ask',
        sessionID: 'ses_other',
        model: null,
      }),
      '{partial',
    ].join('\n'),
  );
  const all = await readAudit(root);
  assert.equal(all.records.length, 3);
  assert.equal(all.skipped, 1);
  assert.equal((await readAudit(root, { decision: 'allow' })).records.length, 1);
  assert.equal((await readAudit(root, { session: 'ses_other' })).records.length, 1);
  assert.equal((await readAudit(root, { modelOnly: true })).records.length, 2);
  assert.equal((await readAudit(root, { limit: 1 })).records[0].sessionID, 'ses_other');
  await assert.rejects(readAudit(root, { limit: 100000 }));
});
test('viewer bounds file reads and refuses linked log files', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'approval-view-bounds-'));
  const filename = path.join(root, '2026-09-12.jsonl');
  await writeFile(filename, 'x'.repeat(2 * 1024 * 1024) + '\n' + JSON.stringify(entry) + '\n');
  const result = await readAudit(root);
  assert.equal(result.limited, true);
  assert.equal(result.records.length, 1);
  await symlink(filename, path.join(root, '2026-09-13.jsonl'));
  await assert.rejects(readAudit(root));
});
test('shadow display distinguishes actual native allow from review ask', () => {
  const record = normalizeRecord({ ...entry, mode: 'shadow', proposed: 'ask', applied: 'allow' });
  assert.match(formatRecord(record), /ALLOW.*shadow, proposed ask/);
});
test('async audit coalesces states before filtering and never calls a pending intent ALLOW', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'approval-async-audit-'));
  const v3 = { ...entry, version: 3, requestID: 'per_job' };
  await writeFile(
    path.join(root, '2026-09-12.jsonl'),
    [
      { ...v3, status: 'queued', applied: 'pending', proposed: 'ask' },
      { ...v3, status: 'grant_pending', applied: 'pending' },
      { ...v3, status: 'allow', applied: 'allow' },
      { ...v3, requestID: 'per_retry', status: 'retrying', applied: 'pending', proposed: 'ask' },
    ]
      .map((x) => JSON.stringify(x) + '\n')
      .join(''),
  );
  const all = await readAudit(root);
  assert.equal(all.records.length, 2);
  assert.equal((await readAudit(root, { decision: 'ask' })).records.length, 0);
  assert.equal((await readAudit(root, { decision: 'allow' })).records.length, 1);
  assert.match(formatRecord(all.records[1]), /RETRYING/);
  assert.doesNotMatch(
    formatRecord(normalizeRecord({ ...v3, status: 'grant_pending', applied: 'pending' })),
    /ALLOW → permission granted/,
  );
});

test('notification scans filter after latest state and can find active requests beyond recent allows', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'approval-notification-audit-'));
  const v3 = {
    ...entry,
    version: 3,
    proposed: 'ask',
    applied: 'ask',
    status: 'ask',
    requestID: 'per_pending',
  };
  await writeFile(
    path.join(root, '2026-09-12.jsonl'),
    [
      v3,
      { ...v3, requestID: 'per_done' },
      { ...v3, requestID: 'per_done', status: 'allow', applied: 'allow' },
      { ...v3, requestID: 'per_scoped', action: 'scoped_permission' },
      { ...v3, requestID: 'per_shadow', mode: 'shadow' },
      ...Array.from({ length: 250 }, (_, i) => ({
        ...v3,
        requestID: 'per_' + i,
        status: 'allow',
        applied: 'allow',
      })),
    ]
      .map((x) => JSON.stringify(x) + '\n')
      .join(''),
  );
  assert.deepEqual(
    (await readAudit(root, { pendingOnly: true })).records.map((r) => r.requestID),
    ['per_pending'],
  );
  assert.equal(
    (await readAudit(root, { pendingOnly: true, excludeKeys: new Set(['ses_test:per_pending']) }))
      .records.length,
    0,
  );
  assert.equal((await readAudit(root, { requestIDs: ['per_done'] })).records[0].applied, 'allow');
  await assert.rejects(readAudit(root, { maxFileBytes: 100 * 1024 * 1024 }));
});
