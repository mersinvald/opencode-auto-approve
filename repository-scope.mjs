import path from 'node:path';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { digest, within } from './policy.mjs';

async function small(file) {
  const st = await lstat(file);
  if (!st.isFile() || st.size > 65536) throw Error('invalid_repository_metadata');
  return readFile(file, 'utf8');
}

// Read Git's checkout linkage. Never execute a repository hook or shell command.
export async function repositoryScope(directory) {
  let root = await realpath(directory);
  if (!(await lstat(root)).isDirectory()) root = path.dirname(root);
  for (let depth = 0; depth < 40; depth++) {
    const marker = path.join(root, '.git');
    try {
      const st = await lstat(marker);
      if (st.isSymbolicLink()) return null;
      let gitDir,
        markerText = null,
        commonText = null;
      if (st.isDirectory()) gitDir = marker;
      else {
        markerText = await small(marker);
        const match = /^gitdir: ([^\r\n]+)\r?\n?$/.exec(markerText);
        if (!match) return null;
        gitDir = await realpath(path.resolve(root, match[1]));
      }
      let commonDir = gitDir;
      try {
        commonText = (await small(path.join(gitDir, 'commondir'))).trim();
        commonDir = await realpath(path.resolve(gitDir, commonText));
      } catch (e) {
        if (e.code !== 'ENOENT') return null;
      }
      if (gitDir !== commonDir) {
        if (!within(gitDir, path.join(commonDir, 'worktrees'))) return null;
        const backlink = (await small(path.join(gitDir, 'gitdir'))).trim();
        if ((await realpath(backlink)) !== marker) return null;
      }
      const identity = await lstat(commonDir);
      if (!identity.isDirectory()) return null;
      return {
        root,
        gitDir,
        commonDir,
        worktree: gitDir !== commonDir,
        identity: digest({ commonDir, dev: identity.dev, ino: identity.ino }),
        linkage: digest({ markerText, commonText, root, gitDir, commonDir }),
      };
    } catch (e) {
      if (e.code !== 'ENOENT') return null;
    }
    const parent = path.dirname(root);
    if (parent === root) return null;
    root = parent;
  }
  return null;
}
