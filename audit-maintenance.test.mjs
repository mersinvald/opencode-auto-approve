import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  lstat,
  open,
  rm,
  symlink,
  readdir,
} from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  scanAuditStorage,
  storageWarning,
  checkAuditStorage,
  scheduleAuditMaintenance,
  vacuumAudit,
  parseAuditSize,
  AUDIT_SIZE_BYTES,
} from './audit-maintenance.mjs';
import { writeDetail, sanitizeAudit, readDetail } from './audit-detail.mjs';
import { writeAudit } from './audit-storage.mjs';
import { readAudit, normalizeRecord, formatRecord, formatDetailedRecord } from './audit-view.mjs';
const now = Date.parse('2026-09-15T12:00:00Z');
const base = await mkdtemp(realpathSync(os.tmpdir()) + '/audit-maintenance-');
test.after(() => rm(base, { recursive: true, force: true }));
async function fixture() {
  return mkdtemp(base + '/case-');
}
async function log(root, day, extra = {}) {
  const record = {
    version: 3,
    time: day + 'T00:00:00Z',
    proposed: 'allow',
    applied: 'allow',
    sessionID: 'ses_fixture',
    ...extra,
  };
  await writeFile(path.join(root, day + '.jsonl'), JSON.stringify(record) + '\n', { mode: 0o600 });
}

test('storage thresholds are warnings only and use strict greater-than comparisons', () => {
  assert.equal(
    storageWarning({ bytes: AUDIT_SIZE_BYTES, oldestDay: '2026-09-01', oldestAgeDays: 14 }, now),
    null,
  );
  const size = storageWarning(
    { bytes: AUDIT_SIZE_BYTES + 1, oldestDay: '2026-09-01', oldestAgeDays: 14 },
    now,
  );
  assert.deepEqual(size.storage.triggered, ['size']);
  const age = storageWarning({ bytes: 1, oldestDay: '2026-08-31', oldestAgeDays: 15 }, now);
  assert.deepEqual(age.storage.triggered, ['age']);
  assert.equal(age.kind, 'maintenance');
  assert.match(age.reason, /vacuum --dry-run/);
});

test('inventory includes summaries and orphan details but ignores unrelated files', async () => {
  const root = await fixture();
  await log(root, '2026-09-15');
  const old = await writeDetail(root, sanitizeAudit({ helper: 'old evidence' }), '2026-08-01');
  await writeFile(root + '/unrelated.bin', 'not audit data');
  await mkdir(root + '/details/9999-99-99', { mode: 0o700 });
  const snapshot = await scanAuditStorage(root, now);
  assert.equal(snapshot.files.length, 2);
  assert.equal(snapshot.oldestDay, '2026-08-01');
  assert.equal(snapshot.oldestAgeDays, 45);
  assert.equal(snapshot.bytes, (await lstat(root + '/2026-09-15.jsonl')).size + old.bytes);
  assert.equal((await scanAuditStorage(root + '/missing', now)).bytes, 0);
});

test('warnings persist once per day and trigger set across concurrent callers', async () => {
  const root = await fixture();
  const sparse = await open(root + '/2026-08-01.jsonl', 'w', 0o600);
  await sparse.truncate(AUDIT_SIZE_BYTES + 1);
  await sparse.close();
  const calls = await Promise.all([checkAuditStorage(root, now), checkAuditStorage(root, now)]);
  assert.equal(calls.filter((c) => c.written).length, 1);
  const rows = (await readFile(root + '/2026-09-15.jsonl', 'utf8'))
    .trim()
    .split('\n')
    .map(JSON.parse);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].storage.triggered, ['age', 'size']);
  assert.equal((await checkAuditStorage(root, now)).written, false);
  assert.equal((await checkAuditStorage(root, now + 86400000)).written, true);
  assert.equal((await lstat(root + '/2026-08-01.jsonl')).size, AUDIT_SIZE_BYTES + 1);
});

test('warning renderers never treat storage maintenance as a permission request', async () => {
  const root = await fixture();
  await log(root, '2026-08-01');
  const { warning } = await checkAuditStorage(root, now);
  const record = normalizeRecord(warning);
  for (const format of [formatRecord, formatDetailedRecord]) {
    const text = format(record, { color: 'always' });
    assert.match(text, /WARNING/);
    assert.match(text, /\x1b\[/);
    assert.doesNotMatch(text, /LEGACY|APPROVAL NEEDED|GRANTS|permission granted/);
  }
  assert.equal((await readAudit(root, { limit: 1 })).records[0].kind, 'maintenance');
  assert.equal((await readAudit(root, { decision: 'ask' })).records.length, 0);
  assert.equal((await readAudit(root, { pendingOnly: true })).records.length, 0);
});

test('writer schedules the warning without pruning or changing the permission outcome', async () => {
  const root = await fixture();
  await log(root, '2000-01-01');
  await writeAudit(root, {
    version: 3,
    time: new Date().toISOString(),
    proposed: 'allow',
    applied: 'allow',
  });
  await scheduleAuditMaintenance(root);
  const records = (await readAudit(root)).records;
  assert.ok(records.some((r) => r.kind === 'maintenance'));
  assert.ok(records.some((r) => r.applied === 'allow'));
  assert.ok(await lstat(root + '/2000-01-01.jsonl'));
  const before = await readdir(root);
  await scheduleAuditMaintenance(root);
  assert.deepEqual(await readdir(root), before);
});

test('vacuum preview is read-only; apply removes only old known audit files', async () => {
  const root = await fixture();
  await log(root, '2026-08-31');
  await log(root, '2026-09-01');
  await log(root, '2026-09-15');
  const old = await writeDetail(root, sanitizeAudit({ old: true }), '2026-08-31');
  const current = await writeDetail(root, sanitizeAudit({ current: true }), '2026-09-15');
  await writeFile(root + '/notes.txt', 'keep');
  await writeFile(root + '/details/2026-08-31/notes.txt', 'keep this too');
  const before = await scanAuditStorage(root, now);
  const preview = await vacuumAudit(root, { now, dryRun: true });
  assert.deepEqual(preview.files.sort(), ['2026-08-31.jsonl', old.path].sort());
  assert.deepEqual(await scanAuditStorage(root, now), before);
  const applied = await vacuumAudit(root, { now });
  assert.equal(applied.bytesReclaimed, preview.bytesReclaimed);
  await assert.rejects(lstat(root + '/' + old.path), { code: 'ENOENT' });
  assert.ok(await readDetail(root, current));
  assert.ok(await lstat(root + '/2026-09-01.jsonl'));
  assert.equal(await readFile(root + '/notes.txt', 'utf8'), 'keep');
  assert.equal(await readFile(root + '/details/2026-08-31/notes.txt', 'utf8'), 'keep this too');
  assert.equal((await vacuumAudit(root, { now })).files.length, 0);
});

test('vacuum preserves old detail files referenced by retained summaries', async () => {
  const root = await fixture();
  const old = await writeDetail(root, sanitizeAudit({ shared: true }), '2026-08-01');
  await log(root, '2026-08-01', { details: old });
  await log(root, '2026-09-15', { details: old });
  const result = await vacuumAudit(root, { now });
  assert.deepEqual(result.files, ['2026-08-01.jsonl']);
  assert.deepEqual(result.protectedFiles, [old.path]);
  assert.ok(await readDetail(root, old));
});

test('size cleanup removes oldest prior days but protects today even above target', async () => {
  const root = await fixture();
  for (const day of ['2026-09-13', '2026-09-14', '2026-09-15']) await log(root, day);
  const todayBytes = (await lstat(root + '/2026-09-15.jsonl')).size;
  const result = await vacuumAudit(root, { now, maxBytes: todayBytes - 1 });
  assert.deepEqual(result.files, ['2026-09-13.jsonl', '2026-09-14.jsonl']);
  assert.equal(result.bytesAfter, todayBytes);
  assert.equal(result.targetReached, false);
  assert.ok(await lstat(root + '/2026-09-15.jsonl'));
});

test('invalid retained JSON aborts cleanup before removing old data', async () => {
  const root = await fixture();
  await log(root, '2026-08-01');
  await writeFile(root + '/2026-09-15.jsonl', '{partial', { mode: 0o600 });
  await assert.rejects(vacuumAudit(root, { now }), /invalid or incomplete JSON/);
  assert.ok(await lstat(root + '/2026-08-01.jsonl'));
});

test('vacuum rejects links and unsafe storage paths before deletion', async () => {
  for (const kind of ['root', 'summary', 'detail-directory', 'detail-file']) {
    const root = await fixture(),
      outside = await fixture();
    await log(root, '2026-08-01');
    if (kind === 'root') {
      await symlink(root, outside + '/linked');
      await assert.rejects(vacuumAudit(outside + '/linked', { now }), /Unsafe audit/);
    } else if (kind === 'summary') {
      await symlink(root + '/2026-08-01.jsonl', root + '/2026-08-02.jsonl');
      await assert.rejects(vacuumAudit(root, { now }), /Unsafe audit/);
    } else {
      await mkdir(root + '/details', { mode: 0o700 });
      if (kind === 'detail-directory') await symlink(outside, root + '/details/2026-08-01');
      else {
        await mkdir(root + '/details/2026-08-01', { mode: 0o700 });
        await symlink(
          root + '/2026-08-01.jsonl',
          root + '/details/2026-08-01/' + 'a'.repeat(64) + '.json',
        );
      }
      await assert.rejects(vacuumAudit(root, { now }), /Unsafe audit/);
    }
    assert.ok(await lstat(root + '/2026-08-01.jsonl'));
  }
});

test('CLI vacuum accepts the installed policy prefix, validates flags, and reports preview and apply', async () => {
  const root = await fixture(),
    policy = root + '/policy.json';
  await log(root, '2000-01-01');
  await writeFile(policy, JSON.stringify({ auditRoot: root }), { mode: 0o600 });
  const cli = fileURLToPath(new URL('./audit-view.mjs', import.meta.url));
  const run = (...args) =>
    execFileSync(process.execPath, [cli, '--policy', policy, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  assert.match(run('--help'), /vacuum/);
  assert.match(run('vacuum', '--dry-run', '--color', 'always'), /\x1b\[/);
  const plan = JSON.parse(run('vacuum', '--dry-run', '--json'));
  assert.equal(plan.dryRun, true);
  assert.ok(await lstat(root + '/2000-01-01.jsonl'));
  for (const args of [
    ['vacuum', '--keep-days', '-1'],
    ['vacuum', '--max-size', 'no'],
    ['vacuum', '--follow'],
    ['--dry-run'],
    ['vacuum', '--session', 'id'],
  ])
    assert.throws(() => run(...args));
  assert.match(run('vacuum'), /VACUUM COMPLETE/);
  await assert.rejects(lstat(root + '/2000-01-01.jsonl'), { code: 'ENOENT' });
  assert.equal(parseAuditSize('1GiB'), AUDIT_SIZE_BYTES);
  assert.equal(parseAuditSize('1.5MiB'), 1572864);
  for (const invalid of ['0', '-1', 'Infinity', '1TB', '0.1B'])
    assert.throws(() => parseAuditSize(invalid));
});
