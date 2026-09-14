import path from 'node:path';
import { lstat } from 'node:fs/promises';
import { repositoryScope } from './repository-scope.mjs';
import { grant } from './grant-rules.mjs';
import { within } from './policy.mjs';

// Physical paths remain evidence. Only verified linked checkouts get a reusable
// repository-relative identity. A pathname containing "worktree" proves nothing.
export async function worktreeGrant(item) {
  if (!['file', 'directory'].includes(item.targetType) || item.space) return item;
  let existing = item.target;
  while (
    !(await lstat(existing).catch((e) => {
      if (e.code !== 'ENOENT') throw e;
      return null;
    }))
  ) {
    const parent = path.dirname(existing);
    if (parent === existing) return item;
    existing = parent;
  }
  const repo = await repositoryScope(existing);
  if (!repo?.worktree || !within(item.target, repo.root)) return item;
  return grant(item.operation, path.relative(repo.root, item.target) || '.', item.targetType, {
    ...item,
    space: { repository: repo.identity, modifier: 'scratch' },
    repositoryName: path.basename(path.dirname(repo.commonDir)),
    physicalTarget: item.target,
    binding: { root: repo.root, commonDir: repo.commonDir, linkage: repo.linkage },
  });
}
