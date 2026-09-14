import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, symlink, chmod } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonical } from './policy.mjs';
import { ancestorScratchDirectories, scratchDirectory } from './review-context.mjs';

const base = await canonical(await mkdtemp(path.join(os.tmpdir(), 'approval-ancestor-')), '/');
const config = {
  version: 1,
  mode: 'enforce',
  model: { providerID: 'fixture', id: 'unused', variant: 'medium' },
  skillRoots: [],
  protectedRoots: [],
  scratchRoot: base + '/scratch',
  auditRoot: base + '/audit',
  timeoutMs: 100,
  maxRequestChars: 32000,
};
const dirs = {};
for (const id of ['root', 'middle', 'leaf', 'sibling', 'unrelated'])
  dirs[id] = await scratchDirectory(config.scratchRoot, id);
const infos = {
  root: { id: 'root' },
  middle: { id: 'middle', parentID: 'root' },
  leaf: { id: 'leaf', parentID: 'middle', metadata: { parentID: 'unrelated' } },
  sibling: { id: 'sibling', parentID: 'root' },
};
const session = {
  get: async ({ sessionID }) => {
    if (!infos[sessionID]) throw Error('Missing session');
    return infos[sessionID];
  },
};
const scope = {
  directory: base + '/repo',
  scratch: dirs.leaf,
  readOnly: true,
  readableAncestorScratch: await ancestorScratchDirectories(
    session,
    infos.leaf,
    config.scratchRoot,
  ),
};
await mkdir(scope.directory);
await writeFile(dirs.root + '/report.json', '{}');
const request = (action, target, name = 'read') => ({
  action,
  resources: [target],
  effect: 'ask',
  tool: { name, input: { path: target } },
});

test('readable roots come only from existing private directories of native ancestors', async () => {
  assert.deepEqual(scope.readableAncestorScratch, [dirs.middle, dirs.root]);
  assert.ok(!scope.readableAncestorScratch.includes(dirs.sibling));
  assert.ok(!scope.readableAncestorScratch.includes(dirs.unrelated));
  assert.deepEqual(await ancestorScratchDirectories(session, infos.root, config.scratchRoot), []);
});
test('untrusted directory modes and incomplete or cyclic chains fail closed', async () => {
  await chmod(dirs.middle, 0o777);
  await assert.rejects(ancestorScratchDirectories(session, infos.leaf, config.scratchRoot));
  await chmod(dirs.middle, 0o700);
  await assert.rejects(
    ancestorScratchDirectories(
      { get: async () => ({ id: 'loop', parentID: 'loop' }) },
      { id: 'child', parentID: 'loop' },
      config.scratchRoot,
    ),
  );
  await assert.rejects(
    ancestorScratchDirectories(session, { id: 'child', parentID: 'absent' }, config.scratchRoot),
  );
});
