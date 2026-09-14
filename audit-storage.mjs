import { mkdir, lstat, open, readdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import { writeDetail, pruneDetails } from './audit-detail.mjs';

export async function writeAudit(root, record) {
  await mkdir(root, { recursive: true, mode: 0o700 });
  const stat = await lstat(root);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid() ||
    stat.mode & 0o077
  )
    throw new Error('Unsafe audit directory');
  const { detailPayload, grantDraft, ...summary } = record;
  const stored = detailPayload
    ? { ...summary, details: await writeDetail(root, detailPayload, record.time.slice(0, 10)) }
    : summary;
  const filename = path.join(root, record.time.slice(0, 10) + '.jsonl');
  // O_NOFOLLOW protects the log file from symlink substitution.
  const { constants } = await import('node:fs');
  const file = await open(
    filename,
    constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const st = await file.stat();
    if (!st.isFile() || st.uid !== process.getuid() || st.mode & 0o077)
      throw new Error('Unsafe audit file');
    if (st.size > 10 * 1024 * 1024) throw new Error('Daily audit size limit');
    await file.writeFile(JSON.stringify(stored) + '\n');
  } finally {
    await file.close();
  }
  // Bound retention without inspecting unrelated files.
  const cutoff = Date.now() - 14 * 86400000;
  for (const name of await readdir(root)) {
    if (/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(name) && Date.parse(name.slice(0, 10)) < cutoff)
      await unlink(path.join(root, name));
  }
  await pruneDetails(root, cutoff);
}
