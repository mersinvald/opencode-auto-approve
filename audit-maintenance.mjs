import { constants } from 'node:fs';
import { lstat, readdir, open, unlink } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import path from 'node:path';

export const AUDIT_AGE_DAYS = 14;
export const AUDIT_SIZE_BYTES = 1024 ** 3;
const DAY = 86400000;
const checks = new Map();
const datePattern = /^\d{4}-\d{2}-\d{2}$/;
const detailPattern = /^details\/\d{4}-\d{2}-\d{2}\/[a-f0-9]{64}\.json$/;
const dayAt = (now) => new Date(now).toISOString().slice(0, 10);
const validDay = (day) =>
  datePattern.test(day) && Number.isFinite(Date.parse(day)) && dayAt(Date.parse(day)) === day;

async function privateStat(filename, directory = false) {
  const st = await lstat(filename);
  if (
    st.isSymbolicLink() ||
    st.uid !== process.getuid() ||
    st.mode & 0o077 ||
    !(directory ? st.isDirectory() : st.isFile())
  )
    throw Error('Unsafe audit storage path: ' + filename);
  return st;
}
const identity = (st) => ({
  dev: st.dev,
  ino: st.ino,
  size: st.size,
  mtimeMs: st.mtimeMs,
  ctimeMs: st.ctimeMs,
});
const unchanged = (a, b) => Object.keys(identity(a)).every((key) => a[key] === b[key]);

// Inspect only files owned by the audit writer. Do not traverse unrelated data or links.
export async function scanAuditStorage(root, now = Date.now()) {
  const files = [];
  try {
    await privateStat(root, true);
  } catch (error) {
    if (error.code === 'ENOENT') return { files, bytes: 0, oldestDay: null, oldestAgeDays: 0 };
    throw error;
  }
  const add = async (relativePath, day, kind) => {
    const st = await privateStat(path.join(root, relativePath));
    files.push({ path: relativePath, day, kind, ...identity(st) });
  };
  for (const name of await readdir(root)) {
    if (/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(name) && validDay(name.slice(0, 10)))
      await add(name, name.slice(0, 10), 'summary');
    const marker = /^\.storage-warning-(\d{4}-\d{2}-\d{2})-(age|size|age-size)\.json$/.exec(name);
    if (marker && validDay(marker[1])) await add(name, marker[1], 'marker');
  }
  const base = path.join(root, 'details');
  try {
    await privateStat(base, true);
    for (const day of await readdir(base)) {
      if (!validDay(day)) continue;
      await privateStat(path.join(base, day), true);
      for (const name of await readdir(path.join(base, day))) {
        if (/^[a-f0-9]{64}\.json$/.test(name))
          await add(path.join('details', day, name), day, 'detail');
      }
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const oldestDay = files.map((f) => f.day).sort()[0] ?? null;
  return {
    files,
    bytes: files.reduce((sum, f) => sum + f.size, 0),
    oldestDay,
    oldestAgeDays: oldestDay
      ? Math.max(0, (Date.parse(dayAt(now)) - Date.parse(oldestDay)) / DAY)
      : 0,
  };
}

export function storageWarning(snapshot, now = Date.now()) {
  const triggered = [];
  if (snapshot.oldestAgeDays > AUDIT_AGE_DAYS) triggered.push('age');
  if (snapshot.bytes > AUDIT_SIZE_BYTES) triggered.push('size');
  if (!triggered.length) return null;
  return {
    version: 3,
    kind: 'maintenance',
    time: new Date(now).toISOString(),
    action: 'audit_storage',
    status: 'warning',
    code: 'audit_storage_warning',
    reason:
      `Audit storage: ${(snapshot.bytes / 1024 ** 3).toFixed(2)} GiB. Oldest day ${snapshot.oldestDay} (${snapshot.oldestAgeDays} days). ` +
      `Threshold exceeded: ${triggered.map((x) => (x === 'age' ? '14 days' : '1 GiB')).join(', ')}. ` +
      'Run oc-approvals vacuum --dry-run to preview cleanup. No data was deleted.',
    storage: {
      bytes: snapshot.bytes,
      oldestDay: snapshot.oldestDay,
      oldestAgeDays: snapshot.oldestAgeDays,
      triggered,
      thresholds: { ageDays: AUDIT_AGE_DAYS, bytes: AUDIT_SIZE_BYTES },
    },
  };
}

// One warning per UTC day and trigger set, including across OpenCode processes.
export async function checkAuditStorage(root, now = Date.now()) {
  const snapshot = await scanAuditStorage(root, now);
  const warning = storageWarning(snapshot, now);
  if (!warning) return { snapshot, warning: null, written: false };
  const day = dayAt(now);
  const markerPath = path.join(
    root,
    `.storage-warning-${day}-${warning.storage.triggered.join('-')}.json`,
  );
  let marker;
  try {
    marker = await open(
      markerPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
  } catch (error) {
    if (error.code === 'EEXIST') return { snapshot, warning, written: false };
    throw error;
  }
  try {
    await marker.writeFile(JSON.stringify(warning) + '\n');
    const file = await open(
      path.join(root, day + '.jsonl'),
      constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | constants.O_NOFOLLOW,
      0o600,
    );
    try {
      const st = await file.stat();
      if (!st.isFile() || st.uid !== process.getuid() || st.mode & 0o077)
        throw Error('Unsafe audit warning file');
      await file.writeFile(JSON.stringify(warning) + '\n');
    } finally {
      await file.close();
    }
  } catch (error) {
    await unlink(markerPath).catch(() => {});
    throw error;
  } finally {
    await marker.close();
  }
  return { snapshot, warning, written: true };
}

// Run metadata scans outside the permission path, at most once every five minutes.
export function scheduleAuditMaintenance(root) {
  const current = checks.get(root);
  if (current && Date.now() < current.next) return current.promise;
  const state = { next: Infinity, promise: null };
  state.promise = checkAuditStorage(root)
    .catch(() => null)
    .finally(() => {
      state.next = Date.now() + 300000;
    });
  checks.set(root, state);
  return state.promise;
}

export function parseAuditSize(value) {
  const match = /^(\d+(?:\.\d+)?)\s*(B|KiB|MiB|GiB)?$/i.exec(value);
  if (!match) throw Error('Use a positive size in B, KiB, MiB, or GiB');
  const bytes =
    Number(match[1]) *
    { b: 1, kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3 }[(match[2] ?? 'B').toLowerCase()];
  if (!Number.isSafeInteger(bytes) || bytes < 1) throw Error('Invalid audit size');
  return bytes;
}

async function verifyFile(root, file) {
  await privateStat(root, true);
  if (file.kind === 'detail') {
    await privateStat(path.join(root, 'details'), true);
    await privateStat(path.join(root, 'details', file.day), true);
  }
  const st = await privateStat(path.join(root, file.path));
  if (!unchanged(file, st))
    throw Error('Audit data changed during vacuum. Retry when OpenCode is idle');
}

async function retainedReferences(root, summaries) {
  const references = new Set();
  for (const summary of summaries) {
    await verifyFile(root, summary);
    const file = await open(
      path.join(root, summary.path),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      if (!unchanged(summary, await file.stat())) throw Error('Audit log changed during vacuum');
      if (!summary.size) continue;
      const input = file.createReadStream({ autoClose: false, start: 0, end: summary.size - 1 });
      const lines = createInterface({ input, crlfDelay: Infinity });
      try {
        for await (const line of lines) {
          if (!line.trim()) continue;
          let record;
          try {
            record = JSON.parse(line);
          } catch {
            throw Error('Cannot vacuum: a retained audit log contains invalid or incomplete JSON');
          }
          for (const ref of [record.details, record.priorDetails]) {
            if (ref?.status === 'stored' && detailPattern.test(ref.path)) references.add(ref.path);
          }
        }
      } finally {
        lines.close();
        input.destroy();
      }
    } finally {
      await file.close();
    }
  }
  return references;
}

// Delete whole old UTC buckets only when the user invokes vacuum.
export async function vacuumAudit(
  root,
  { keepDays = AUDIT_AGE_DAYS, maxBytes, dryRun = false, now = Date.now() } = {},
) {
  if (!Number.isSafeInteger(keepDays) || keepDays < 0)
    throw Error('Keep days must be a nonnegative integer');
  if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || maxBytes < 1))
    throw Error('Invalid maximum audit size');
  const snapshot = await scanAuditStorage(root, now);
  const today = dayAt(now),
    cutoff = dayAt(Date.parse(today) - keepDays * DAY);
  const days = [...new Set(snapshot.files.map((f) => f.day))].filter((day) => day < today).sort();
  const selected = new Set(days.filter((day) => day < cutoff));
  let remaining =
    snapshot.bytes -
    snapshot.files.filter((f) => selected.has(f.day)).reduce((n, f) => n + f.size, 0);
  if (maxBytes !== undefined) {
    for (const day of days) {
      if (remaining <= maxBytes) break;
      if (selected.has(day)) continue;
      selected.add(day);
      remaining -= snapshot.files.filter((f) => f.day === day).reduce((n, f) => n + f.size, 0);
    }
  }
  let candidates = snapshot.files.filter((f) => selected.has(f.day));
  const retained = snapshot.files.filter((f) => f.kind === 'summary' && !selected.has(f.day));
  // Retained summaries can refer to details stored on an earlier UTC day.
  const references = candidates.length ? await retainedReferences(root, retained) : new Set();
  const protectedFiles = candidates.filter((f) => f.kind === 'detail' && references.has(f.path));
  candidates = candidates.filter((f) => !protectedFiles.includes(f));
  const bytesReclaimed = candidates.reduce((n, f) => n + f.size, 0);
  const result = {
    dryRun,
    keepDays,
    maxBytes: maxBytes ?? null,
    bytesBefore: snapshot.bytes,
    bytesAfter: snapshot.bytes - bytesReclaimed,
    bytesReclaimed,
    files: candidates.map((f) => f.path),
    days: [...selected].sort(),
    protectedFiles: protectedFiles.map((f) => f.path),
    targetReached: maxBytes === undefined || snapshot.bytes - bytesReclaimed <= maxBytes,
  };
  if (!dryRun && candidates.length) {
    // Validate the complete plan before removing any file. Never recursively remove directories.
    for (const file of snapshot.files) await verifyFile(root, file);
    for (const file of candidates.sort((a, b) => (a.kind === 'detail') - (b.kind === 'detail'))) {
      await verifyFile(root, file);
      await unlink(path.join(root, file.path));
    }
    checks.delete(root);
  }
  return result;
}
