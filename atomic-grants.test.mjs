import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { realpathSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile, readFile, readdir, stat, symlink } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gate } from './grant-gate.mjs';
import { grant, grantDescriptor, grantTree, resolveGrants, ruleKey } from './grant-rules.mjs';
import { createRuleStore } from './grant-store.mjs';
import { reviewDynamic } from './grant-review.mjs';
import { sha256 } from './shell-host.mjs';
import { safeSed } from './shell-inspection.mjs';

const base = await mkdtemp(realpathSync(os.tmpdir()) + '/approval-atoms-');
const main = base + '/infra',
  other = base + '/pwa',
  one = base + '/wt-one',
  two = base + '/wt-two',
  three = base + '/wt-pwa';
function git(cwd, ...args) {
  return execFileSync('/usr/bin/git', ['-C', cwd, ...args], { stdio: 'pipe' });
}
for (const repo of [main, other]) {
  await mkdir(repo);
  git(repo, 'init', '-q');
  await mkdir(repo + '/src');
  await writeFile(repo + '/src/file', 'fixture');
  git(repo, 'add', 'src');
  git(
    repo,
    '-c',
    'user.name=Fixture',
    '-c',
    'user.email=fixture@example.invalid',
    '-c',
    'commit.gpgsign=false',
    'commit',
    '-qm',
    'fixture',
  );
}
for (const [repo, wt] of [
  [main, one],
  [main, two],
  [other, three],
])
  git(repo, 'worktree', 'add', '--detach', wt, 'HEAD');
const parser = fileURLToPath(new URL('./bin/shell-parser', import.meta.url));
const config = {
  skillRoots: [],
  protectedRoots: [base + '/policy'],
  timeoutMs: 5000,
  model: { providerID: 'fixture', id: 'fixture', variant: 'medium' },
  staticShell: { enabled: true, parser: { path: parser, sha256: sha256(await readFile(parser)) } },
};
const scope = { directory: main, agent: 'orchestrator' };
const permissions = { projectID: 'multi-repo', saved: [], sessions: [], agent: { rules: [] } };
const edit = (file) => ({
  action: 'edit',
  effect: 'ask',
  directory: main,
  resources: [file],
  tool: { name: 'edit', input: { filePath: file } },
});
const inspect = (request, rules = [], extra = {}) =>
  gate(request, { scope, config, permissions, state: { rules }, ...extra });
const allow = (item) => ({
  ...grantDescriptor(item),
  mode: 'allow',
  scope: 'project',
  authority: 'model',
});

let atom;
test('verified worktrees share atomic identities without sharing other repositories or the main checkout', async () => {
  const first = await inspect(edit(one + '/src/file'));
  atom = first.analysis.grants[0];
  assert.equal(atom.space.modifier, 'scratch');
  assert.equal(atom.target, 'src/file');
  const source = first.candidates.find((c) => c.target === 'src' && c.targetType === 'directory');
  assert.ok(source);
  const second = await inspect(edit(two + '/src/new-file'), [allow(source)]);
  assert.equal(second.decision, 'allow');
  assert.equal((await inspect(edit(two + '/src/file'))).analysis.grants[0].id, atom.id);
  assert.equal((await inspect(edit(three + '/src/file'), [allow(source)])).decision, 'dynamic');
  assert.equal((await inspect(edit(main + '/src/file'), [allow(source)])).decision, 'dynamic');
  assert.equal((await inspect(edit(two + '/outside'), [allow(source)])).decision, 'dynamic');
  assert.notEqual(first.fingerprint, (await inspect(edit(two + '/src/file'))).fingerprint);
  // One project can explicitly hold independent scopes for both repositories.
  const pwa = (await inspect(edit(three + '/src/file'))).candidates.find((c) => c.target === 'src');
  assert.equal(
    (await inspect(edit(three + '/src/new'), [allow(source), allow(pwa)])).decision,
    'allow',
  );
});

test('physical legacy permissions preserve their original boundary and more-specific ask wins', async () => {
  const legacy = {
    operation: 'files.write',
    target: one,
    targetType: 'directory',
    mode: 'allow',
    authority: 'user',
    scope: 'project',
  };
  assert.equal((await inspect(edit(one + '/src/file'), [legacy])).decision, 'allow');
  assert.equal((await inspect(edit(two + '/src/file'), [legacy])).decision, 'dynamic');
  const logical = (await inspect(edit(one + '/src/file'))).candidates.find((c) => c.target === '.');
  const ask = { ...legacy, target: two + '/src/file', targetType: 'file', mode: 'ask' };
  assert.equal((await inspect(edit(two + '/src/file'), [allow(logical), ask])).decision, 'ask');
  assert.equal(
    (
      await inspect(edit(two + '/src/file'), [allow(logical)], {
        scope: { ...scope, readOnly: true },
      })
    ).decision,
    'ask',
  );
  assert.equal(
    (
      await inspect(edit(two + '/src/file'), [allow(logical)], {
        permissions: {
          ...permissions,
          agent: { rules: [{ action: 'edit', resource: two + '/*', effect: 'deny' }] },
        },
      })
    ).decision,
    'ask',
  );
});

test('symlink escapes and unverified worktree names cannot inherit scratch rules', async () => {
  const root = (await inspect(edit(one + '/src/file'))).candidates.find((c) => c.target === '.');
  await symlink(main + '/src/file', one + '/src/escape');
  assert.equal((await inspect(edit(one + '/src/escape'), [allow(root)])).decision, 'dynamic');
  const fake = base + '/worktree-fake';
  await mkdir(fake);
  await mkdir(fake + '/src');
  assert.equal((await inspect(edit(fake + '/src/file'), [allow(root)])).decision, 'dynamic');
  const marker = await readFile(two + '/.git', 'utf8');
  await writeFile(two + '/.git', 'gitdir: ' + base + '/missing\n');
  assert.equal((await inspect(edit(two + '/src/file'), [allow(root)])).decision, 'dynamic');
  await writeFile(two + '/.git', marker);
});

test('incomplete shell analysis retains known atoms but cannot inherit blanket approval', async () => {
  const command = 'cat src/file; python3 unreviewed.py';
  const request = {
    action: 'shell',
    effect: 'ask',
    resources: [command],
    directory: one,
    tool: { name: 'shell', input: { command, workdir: one } },
  };
  const runtime = { command, cwd: one, shell: '/bin/bash', env: { PATH: '/usr/bin:/bin' } };
  const broad = { operation: '*', target: '*', targetType: 'any', mode: 'allow' };
  const checked = await inspect(request, [broad], { runtime });
  assert.equal(checked.analysis.complete, false);
  assert.equal(checked.decision, 'dynamic');
  assert.ok(
    checked.analysis.grants.some((g) => g.operation === 'files.read' && g.target === 'src/file'),
  );
  assert.ok(checked.analysis.grants.every((g) => !g.operation.includes('opaque')));
  assert.ok(checked.analysis.unresolved.length);
  const known = checked.analysis.grants.find((g) => g.operation === 'files.read');
  assert.equal(
    (await inspect(request, [broad, { ...allow(known), mode: 'ask' }], { runtime })).decision,
    'ask',
  );
  let called = false;
  await reviewDynamic(
    {
      request,
      scope,
      config,
      permissions,
      state: { rules: [broad, { ...allow(known), mode: 'ask' }] },
      runtime,
    },
    {
      generate: async () => {
        called = true;
      },
      evidence: async () => ({ users: [], delegation: [] }),
    },
  );
  assert.equal(called, false);
});

test('version 2 migration backs up command history and keeps bounded rules', async () => {
  const policy = base + '/migration/policy.json';
  await mkdir(path.dirname(policy));
  const store = createRuleStore(policy);
  await store.read('project');
  const original = {
    version: 2,
    projectID: 'project',
    revision: 7,
    imported: [],
    rules: [
      {
        operation: 'shell.opaque',
        target: 'old-command-digest',
        targetType: 'exact',
        mode: 'allow',
        authority: 'model',
      },
      {
        operation: 'files.write',
        target: main + '/src',
        targetType: 'directory',
        mode: 'allow',
        authority: 'user',
      },
    ],
    seen: [{ operation: 'shell.opaque', target: 'old-command-digest', targetType: 'exact' }],
  };
  const file = store.directory + '/project.json';
  await writeFile(file, JSON.stringify(original), { mode: 0o600 });
  const current = await store.read('project');
  assert.equal(current.version, 3);
  assert.equal(current.rules.length, 1);
  assert.equal(current.seen.length, 0);
  const backups = (await readdir(store.directory)).filter((n) => n.endsWith('.backup'));
  assert.equal(backups.length, 1);
  const backup = store.directory + '/' + backups[0];
  assert.deepEqual(JSON.parse(await readFile(backup)), original);
  assert.equal((await stat(backup)).mode & 0o077, 0);
  assert.deepEqual(await store.read('project'), current);
  await store.import('project', [
    { projectID: 'project', id: 'wildcard', action: 'shell', resource: 'python3 *' },
  ]);
  assert.equal((await store.read('project')).rules.length, 1);
});

test('logical scopes survive storage and observation without one row per checkout', async () => {
  const root = base + '/logical-store';
  await mkdir(root);
  const store = createRuleStore(root + '/policy.json');
  const a = (await inspect(edit(one + '/src/file'))).analysis.grants[0];
  const b = (await inspect(edit(two + '/src/file'))).analysis.grants[0];
  await store.observe('project', [a], {});
  await store.observe('project', [b], {});
  await store.set('project', a, 'allow', 'model');
  const state = await store.read('project');
  assert.equal(state.seen.length, 1);
  assert.equal(state.seen[0].count, 2);
  assert.equal(resolveGrants([b], state.rules).decision, 'allow');
  assert.equal(resolveGrants([b], (await store.read('another-project')).rules).decision, 'dynamic');
  const nodes = [];
  const walk = (list) =>
    list.forEach((n) => {
      nodes.push(n);
      walk(n.children);
    });
  walk(grantTree(state.seen, state.rules));
  assert.ok(nodes.find((n) => n.space && n.target === '.'));
  assert.ok(!nodes.some((n) => n.target.includes('/wt-')));
  assert.notEqual(ruleKey(a), ruleKey({ ...a, space: { ...a.space, repository: '0'.repeat(64) } }));
  for (const target of ['../escape', '/absolute', 'src/../../outside'])
    assert.throws(() => grant('files.read', target, 'file', { space: a.space }));
});

test('model input contains relevant atoms without whole-store permission history', async () => {
  const request = edit(one + '/src/file'),
    state = { rules: [], seen: [{ label: 'irrelevant-history-marker' }] };
  const p = {
    request,
    scope,
    config,
    permissions: { ...permissions, saved: [{ resource: 'unused-native-marker' }] },
    state,
  };
  const evidence = async () => ({
    users: [{ text: 'Implement the component, including repeated edits in src.' }],
    delegation: [],
  });
  const result = await reviewDynamic(p, {
    evidence,
    refresh: async () => p,
    generate: async ({ prompt }) => {
      assert.ok(!prompt.includes('irrelevant-history-marker'));
      assert.ok(!prompt.includes('unused-native-marker'));
      const data = JSON.parse(prompt.slice(prompt.lastIndexOf('\n') + 1));
      assert.ok(data.grants.some((g) => g.space?.modifier === 'scratch'));
      assert.ok(data.candidates.some((c) => c.target === 'src'));
      return {
        text: JSON.stringify({ decision: 'allow_once', reason: 'Task edit.', remember: [] }),
      };
    },
  });
  assert.equal(result.result.effect, 'allow');
});

test('sed read address ranges never admit embedded execution or output writes', () => {
  for (const p of ['/^def _load/,/return documents/p', '1,$p', '/^a\\/b/,/^end/p'])
    assert.equal(safeSed(p, true), true, p);
  for (const p of [
    '/a/,/b/w /tmp/out',
    '/a/,/b/e',
    '/a/,/b/p; e evil',
    '/a/\np',
    's/a/b/e',
    's/a/b/w /tmp/out',
  ])
    assert.equal(safeSed(p, true), false, p);
});

test('pytest output flags reuse test grants and basetemp includes its deletion effect', async () => {
  const python = '/usr/bin/python3';
  const pinned = {
    ...config,
    staticShell: {
      ...config.staticShell,
      executables: [
        {
          name: 'python3',
          path: python,
          realpath: realpathSync(python),
          sha256: sha256(await readFile(python)),
        },
      ],
    },
  };
  const command =
    'python3 -m pytest src/file -q --no-header --tb=long -W error::UserWarning -p no:cacheprovider --basetemp ../pytest-results';
  const request = {
    action: 'shell',
    effect: 'ask',
    resources: [command],
    directory: one,
    tool: { name: 'shell', input: { command, workdir: one } },
  };
  const runtime = { command, cwd: one, shell: '/bin/bash', env: { PATH: '/usr/bin:/bin' } };
  const initial = await inspect(request, [], { runtime, config: pinned });
  assert.equal(initial.analysis.complete, true, JSON.stringify(initial.analysis));
  assert.ok(
    initial.analysis.grants.some(
      (g) => g.operation === 'files.delete' && g.target === base + '/pytest-results',
    ),
  );
  const granted = initial.analysis.grants.filter((g) => g.operation !== 'files.delete').map(allow);
  assert.equal((await inspect(request, granted, { runtime, config: pinned })).decision, 'dynamic');
  const deletion = initial.analysis.grants.find((g) => g.operation === 'files.delete');
  assert.equal(
    (
      await inspect(request, [...granted, { ...allow(deletion), mode: 'ask' }], {
        runtime,
        config: pinned,
      })
    ).decision,
    'ask',
  );
  assert.equal(
    (await inspect(request, initial.analysis.grants.map(allow), { runtime, config: pinned }))
      .decision,
    'allow',
  );
});

test('migration merges worktree observations and retains explicit legacy restrictions', async () => {
  const root = base + '/migration-worktree';
  await mkdir(root);
  const store = createRuleStore(root + '/policy.json');
  await store.read('project');
  const seen = [one, two].map((wt, i) => ({
    ...grant('files.read', wt + '/src/file'),
    count: i + 1,
    firstSeen: '2026-09-12',
    lastSeen: '2026-09-13',
  }));
  await writeFile(
    store.directory + '/project.json',
    JSON.stringify({
      version: 2,
      projectID: 'project',
      revision: 1,
      imported: [],
      seen,
      rules: [
        {
          operation: 'shell.opaque',
          target: 'legacy',
          targetType: 'exact',
          mode: 'ask',
          authority: 'user',
        },
      ],
    }),
    { mode: 0o600 },
  );
  const state = await store.read('project');
  assert.equal(state.seen.length, 1);
  assert.equal(state.seen[0].count, 3);
  assert.equal(state.seen[0].target, 'src/file');
  assert.equal(state.legacyShellAsk, true);
  assert.equal(state.rules.length, 0);
  const command = 'cat src/file',
    request = {
      action: 'shell',
      effect: 'ask',
      resources: [command],
      directory: one,
      tool: { name: 'shell', input: { command, workdir: one } },
    };
  const checked = await inspect(request, [], {
    state,
    runtime: { command, cwd: one, shell: '/bin/bash', env: { PATH: '/usr/bin:/bin' } },
  });
  assert.equal(checked.decision, 'ask');
});
