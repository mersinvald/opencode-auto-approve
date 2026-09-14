import test from 'node:test';
const sandboxWrapper =
  process.platform === 'darwin'
    ? "/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' "
    : '';

import assert from 'node:assert/strict';
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  symlink,
  link,
  chmod,
  copyFile,
} from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { grant, resolveGrants, grantTree, ruleKey, selectedRulesHash } from './grant-rules.mjs';
import { createRuleStore } from './grant-store.mjs';
import { extractAction } from './action-grants.mjs';
import { gate } from './grant-gate.mjs';
import { decodeToolDecision } from './grant-decision.mjs';
import { reviewDynamic } from './grant-review.mjs';
import { sha256 } from './shell-host.mjs';
import { digest } from './policy.mjs';
import { scriptEvidence } from './review-context.mjs';
import { sanitizeAudit } from './audit-detail.mjs';
import { decodeDecisionResponse } from './structured-classifier.mjs';

const base = await mkdtemp(
    (await import('node:fs')).realpathSync((await import('node:os')).tmpdir()) +
      '/opencode-grant-system-',
  ),
  repo = base + '/pwa',
  worktree = base + '/worktrees/infra/accountant-p01';
await mkdir(repo);
await mkdir(worktree + '/services/finance/accountant', { recursive: true });
await mkdir(base + '/config');
await writeFile(repo + '/README.md', 'fixture');
await writeFile(worktree + '/services/finance/accountant/file.py', 'fixture');
execFileSync('/usr/bin/git', ['init', '-q', worktree]);
const parser = fileURLToPath(new URL('./bin/shell-parser', import.meta.url));
const config = {
  version: 1,
  mode: 'enforce',
  skillRoots: [],
  protectedRoots: [base + '/config'],
  scratchRoot: base + '/scratch',
  auditRoot: base + '/audit',
  model: { providerID: 'fixture', id: 'fixture', variant: 'medium' },
  timeoutMs: 2000,
  maxRequestChars: 32000,
  staticShell: {
    enabled: true,
    parser: { path: parser, sha256: sha256(await readFile(parser)) },
    beadsWriters: ['orchestrator'],
  },
};
const pythonPath = '/usr/bin/python3';
config.staticShell.executables = [
  {
    name: 'python3',
    path: pythonPath,
    realpath: (await import('node:fs')).realpathSync(pythonPath),
    sha256: sha256(await readFile(pythonPath)),
  },
];

const scope = { directory: repo, scratch: base + '/scratch', agent: 'orchestrator' };
const permissions = {
  projectID: 'pwa',
  saved: [
    {
      id: 'psv_worktree',
      projectID: 'pwa',
      action: 'external_directory',
      resource: worktree + '/*',
    },
  ],
  sessions: [],
  agent: { rules: [] },
};
const shell = (command) => ({
  action: 'shell',
  effect: 'ask',
  resources: [command],
  directory: repo,
  tool: { name: 'shell', input: { command, workdir: worktree } },
});
const host = (request) => ({
  command: request.tool.input.command,
  cwd: worktree,
  shell: '/bin/bash',
  env: { PATH: '/usr/bin:/bin' },
});
const rule = (operation, target, mode = 'allow', targetType = 'directory') => ({
  operation,
  target,
  mode,
  targetType,
  scope: 'project',
  authority: 'user',
});

test('specific path and operation override broader rules, including Dynamic', () => {
  const item = grant('files.read', worktree + '/services/finance/accountant/file.py');
  const broad = rule('files.*', worktree, 'ask');
  assert.equal(resolveGrants([item], [broad]).decision, 'ask');
  const specific = rule('files.read', worktree + '/services', 'allow');
  assert.equal(resolveGrants([item], [broad, specific]).decision, 'allow');
  assert.equal(
    resolveGrants([item], [broad, specific, rule('files.read', item.target, 'dynamic', 'file')])
      .decision,
    'dynamic',
  );
  assert.equal(
    resolveGrants([item], [rule('files.read', worktree + '-other')]).decision,
    'dynamic',
  );
  assert.equal(resolveGrants([item], [rule('files.read', '/')]).decision, 'allow');
});
test('tree contains generalized ancestors and separate operation leaves', () => {
  const items = [
    grant('files.read', worktree + '/services/finance/accountant/file.py'),
    grant('files.write', repo + '/README.md'),
  ];
  const tree = grantTree(items, [rule('files.read', worktree)]);
  assert.equal(tree.length, 2);
  assert.ok(tree.every((x) => x.targetType === 'any'));
  const flatten = (nodes) => nodes.flatMap((n) => [n, ...flatten(n.children)]);
  const rows = flatten(tree);
  assert.equal(rows.find((n) => n.target === items[0].target).mode, 'allow');
  assert.ok(rows.some((n) => n.target === worktree + '/services' && n.targetType === 'directory'));
});
test('migration is idempotent, preserves bounded permissions, and neutralizes Python wildcards', async () => {
  const store = createRuleStore(base + '/config/policy.json');
  const native = [
    ...permissions.saved,
    { id: 'psv_python', projectID: 'pwa', action: 'shell', resource: 'python3 *' },
    { id: 'psv_edit', projectID: 'pwa', action: 'edit', resource: '*' },
  ];
  const first = await store.import('pwa', native);
  assert.equal(first.rules.find((r) => r.operation === 'shell.opaque').mode, 'dynamic');
  const read = grant('files.read', worktree + '/services/finance/accountant/file.py');
  assert.equal(resolveGrants([read], first.rules).decision, 'allow');
  assert.equal(
    resolveGrants([grant('beads.update', worktree, 'directory')], first.rules).decision,
    'dynamic',
  );
  assert.deepEqual(await store.import('pwa', native), first);
  await store.set('pwa', read, 'ask');
  const after = await store.import('pwa', native);
  assert.equal(resolveGrants([read], after.rules).decision, 'ask');
  assert.deepEqual((await store.read('another_project')).rules, []);
});
test('concurrent rule updates retain both user decisions', async () => {
  const store = createRuleStore(base + '/config/policy.json');
  await Promise.all([
    store.set('concurrent', grant('files.read', repo + '/a'), 'allow'),
    store.set('concurrent', grant('files.write', repo + '/b'), 'ask'),
  ]);
  assert.equal((await store.read('concurrent')).rules.length, 2);
  await assert.rejects(
    store.set('concurrent', grant('files.read', repo + '/c'), 'allow', 'model', {}, 'stale'),
    /changed/,
  );
});
test('reported worktree command resolves all grants without the model', async () => {
  const request = shell(
    "git status --porcelain=v1 --untracked-files=all; printf '\\nHEAD '; git rev-parse HEAD; printf '\\nfiles '; find services/finance/accountant -type f -not -path '*/__pycache__/*' | wc -l; printf '\\nother-status\\n'; git status --porcelain=v1 --untracked-files=all | grep -v '^?? services/finance/accountant/' || true",
  );
  const store = createRuleStore(base + '/config/policy.json');
  const state = await store.import(
    'reported',
    permissions.saved.map((r) => ({ ...r, projectID: 'reported' })),
  );
  const result = await gate(request, {
    scope,
    config,
    runtime: host(request),
    permissions: { ...permissions, projectID: 'reported' },
    state,
  });
  assert.equal(result.analysis.complete, true, JSON.stringify(result.analysis));
  assert.equal(result.decision, 'allow', JSON.stringify(result.resolution));
  assert.ok(
    result.analysis.grants.some((g) => g.operation === 'git.read' && g.target === worktree),
  );
});
test('saved worktree directory access and descendants use the same gate', async () => {
  const request = {
    action: 'external_directory',
    effect: 'allow',
    directory: repo,
    resources: [worktree + '/services/*'],
    tool: { name: 'shell', input: { command: 'find .', workdir: worktree } },
  };
  const state = { rules: [rule('files.access', worktree)] };
  assert.equal((await gate(request, { scope, config, permissions, state })).decision, 'allow');
  assert.equal(
    (
      await gate(
        { ...request, resources: [worktree + '-other/*'] },
        { scope, config, permissions, state },
      )
    ).decision,
    'dynamic',
  );
});
test('every native action becomes grants, including unknown tools', async () => {
  for (const action of [
    'read',
    'edit',
    'external_directory',
    'glob',
    'grep',
    'webfetch',
    'mcp.github.create_issue',
    'execute',
    'custom_operation',
  ]) {
    const result = await extractAction(
      {
        action,
        effect: 'ask',
        directory: repo,
        resources: [repo + '/README.md'],
        tool: { name: action, input: { url: 'https://example.org' } },
      },
      { scope, config },
    );
    assert.ok(result.grants.length, action);
    assert.ok(
      result.grants.every((g) => g.id.startsWith('g_')),
      action,
    );
  }
});
test('global AGENTS read directory gate uses the same instructions grant', async () => {
  await writeFile(base + '/config/AGENTS.md', 'Fixture instructions.');
  const request = {
    action: 'external_directory',
    effect: 'ask',
    directory: repo,
    resources: [base + '/config/*'],
    tool: { name: 'read', input: { filePath: base + '/config/AGENTS.md' } },
  };
  const result = await gate(request, { scope, config, permissions, state: { rules: [] } });
  assert.equal(result.decision, 'allow');
  assert.equal(result.analysis.grants[0].operation, 'instructions.read');
  const edited = await gate(
    { ...request, tool: { name: 'edit', input: { filePath: base + '/config/AGENTS.md' } } },
    { scope, config, permissions, state: { rules: [] } },
  );
  assert.equal(edited.decision, 'dynamic');
});
test('unknown shell effects never inherit an allow from partial read grants', async () => {
  for (const command of [
    'cat services/finance/accountant/file.py; python3 dangerous.py',
    'find services -exec rm {} \\;',
    'find services -delete',
    'cat $(python3 dangerous.py)',
    'D=/tmp; echo ok | D=/secret; cat "$D/file"',
    'cat file 2>&1$(touch /tmp/unsafe)',
  ]) {
    const request = shell(command),
      result = await gate(request, {
        scope,
        config,
        runtime: host(request),
        permissions,
        state: { rules: [rule('files.*', '/')] },
      });
    assert.equal(result.analysis.complete, false, command);
    assert.equal(result.decision, 'dynamic', command);
    assert.ok(
      result.analysis.grants.some((g) => g.operation === 'shell.opaque'),
      command,
    );
  }
});
test('branches collect grants from both outcomes without executing the condition', async () => {
  const request = shell(
    'if grep -q fixture services/finance/accountant/file.py; then cat services/finance/accountant/file.py; else head -n 1 services/finance/accountant/file.py; fi',
  );
  const result = await extractAction(request, { scope, config, runtime: host(request) });
  assert.equal(result.complete, true, JSON.stringify(result));
  assert.deepEqual(
    result.commands.map((c) => c.argv[0]),
    ['grep', 'cat', 'head'],
  );
});
test('native deny and role restrictions take precedence', async () => {
  const request = {
    action: 'edit',
    effect: 'ask',
    directory: repo,
    resources: [repo + '/README.md'],
    tool: { name: 'edit' },
  };
  const args = { scope, config, permissions, state: { rules: [rule('files.write', repo)] } };
  assert.equal(
    (await gate(request, { ...args, scope: { ...scope, readOnly: true } })).decision,
    'ask',
  );
  assert.equal(
    (
      await gate(request, {
        ...args,
        permissions: {
          ...permissions,
          agent: { rules: [{ action: 'edit', resource: '*', effect: 'deny' }] },
        },
      })
    ).decision,
    'ask',
  );
});
test('opaque grants cannot carry writer approval into a restricted role', async () => {
  const request = {
    action: 'custom_operation',
    effect: 'ask',
    directory: repo,
    resources: ['fixture'],
    tool: { name: 'custom_operation', input: { case: 'fixture' } },
  };
  const first = await extractAction(request, { scope, config, permissions });
  const state = {
    rules: first.grants.map((g) => ({ ...g, mode: 'allow', scope: 'project', authority: 'model' })),
  };
  const second = await gate(request, {
    scope: { ...scope, readOnly: true },
    config,
    permissions,
    state,
  });
  assert.equal(second.decision, 'dynamic');
});
test('symlink escape and policy writes have their own grants', async () => {
  await writeFile(base + '/config/secret', 'private');
  await symlink(base + '/config/secret', repo + '/escape');
  const request = {
    action: 'edit',
    effect: 'ask',
    directory: repo,
    resources: [repo + '/escape'],
    tool: { name: 'edit' },
  };
  const result = await gate(request, {
    scope,
    config,
    permissions,
    state: { rules: [rule('files.write', repo)] },
  });
  assert.equal(result.decision, 'dynamic');
  assert.equal(result.analysis.grants[0].operation, 'policy.write');
});
test('copying into a directory checks the actual destination child', async () => {
  await mkdir(worktree + '/copy-dest');
  await writeFile(worktree + '/input', 'fixture');
  await symlink(base + '/config/secret', worktree + '/copy-dest/input');
  const request = shell('cp input copy-dest');
  const result = await gate(request, {
    scope,
    config,
    runtime: host(request),
    permissions,
    state: { rules: [rule('files.*', worktree)] },
  });
  assert.equal(result.decision, 'dynamic');
  assert.ok(
    result.analysis.grants.some(
      (g) => g.operation === 'policy.write' && g.target === base + '/config/secret',
    ),
  );
});
test('exact helper grants change when helper source changes', async () => {
  const filename = worktree + '/helper.py';
  await writeFile(filename, "print('first')\n");
  const request = shell('python3 ' + filename);
  request.scripts = await scriptEvidence(request.tool, scope, config);
  const first = await extractAction(request, { scope, config, runtime: host(request) });
  const item = first.grants.find((g) => g.operation === 'shell.opaque');
  assert.ok(item);
  await writeFile(filename, "print('changed')\n");
  request.scripts = await scriptEvidence(request.tool, scope, config);
  const second = await gate(request, {
    scope,
    config,
    runtime: host(request),
    permissions,
    state: { rules: [{ ...item, mode: 'allow', scope: 'project', authority: 'user' }] },
  });
  assert.equal(second.decision, 'dynamic');
  assert.notEqual(second.analysis.grants.find((g) => g.operation === 'shell.opaque').id, item.id);
});
test('model contract has exactly three decisions and no citation schema', () => {
  const id = grant('files.read', repo + '/README.md').id;
  assert.deepEqual(
    decodeToolDecision({
      decision: 'allow_always',
      reason: 'Repeated reads are authorized.',
      remember: id,
    }).remember,
    [id],
  );
  assert.ok(
    decodeToolDecision({ decision: 'allow_once', reason: 'Task verification.', remember: 'none' }),
  );
  for (const value of [
    { decision: 'allow_always', reason: 'x', remember: 'python3 *' },
    { decision: 'allow_once', reason: 'x', remember: id },
    { decision: 'deny', reason: 'x', remember: 'none' },
  ])
    assert.equal(decodeToolDecision(value), null);
});
test('model approvals use context without grant quotes; concurrent rule changes invalidate the result', async () => {
  const request = {
    action: 'read',
    effect: 'ask',
    directory: repo,
    resources: [worktree + '/services/finance/accountant/file.py'],
    tool: { name: 'read' },
  };
  for (const change of [false, true]) {
    let state = { rules: [] };
    const prepared = {
      request: structuredClone(request),
      scope,
      config,
      permissions: { ...permissions, saved: [] },
      state,
    };
    const result = await reviewDynamic(prepared, {
      evidence: async () => ({
        users: [{ id: 'u', text: 'Inspect the infra worktree.' }],
        delegation: [],
      }),
      refresh: async () => ({ ...prepared, request: structuredClone(request), state }),
      generate: async () => {
        if (change) state = { rules: [rule('files.read', worktree, 'ask')] };
        return {
          text: JSON.stringify({
            decision: 'allow_once',
            reason: 'Authorized read.',
            remember: [],
          }),
        };
      },
    });
    assert.equal(result.result.effect, change ? 'ask' : 'allow', JSON.stringify(result));
    if (!change) assert.equal(result.result.code, 'model_allow_once');
  }
});

test('unrelated rule changes do not restart review or block saving selected rules', async () => {
  const request = {
    action: 'edit',
    effect: 'ask',
    directory: repo,
    resources: [worktree + '/services/finance/accountant/file.py'],
    tool: { name: 'edit' },
  };
  let state = { rules: [] },
    selected;
  const prepared = { request: structuredClone(request), scope, config, permissions, state };
  const result = await reviewDynamic(prepared, {
    evidence: async () => ({
      users: [{ id: 'u', text: 'Implement and repeatedly verify the accountant component.' }],
      delegation: [],
    }),
    refresh: async () => ({ ...prepared, request: structuredClone(request), state }),
    generate: async ({ prompt }) => {
      const data = JSON.parse(prompt.split('\n').at(-1));
      selected = data.candidates.find(
        (c) =>
          c.target === worktree + '/services/finance/accountant' && c.targetType === 'directory',
      );
      assert.ok(selected);
      assert.ok(data.candidates.some((c) => c.target === worktree + '/services/finance'));
      state = { rules: [rule('files.write', repo + '/unrelated')] };
      return {
        text: JSON.stringify({
          decision: 'allow_always',
          reason: 'Repeated component edits authorized.',
          remember: [selected.id],
        }),
      };
    },
  });
  assert.equal(result.result.effect, 'allow', JSON.stringify(result));
  assert.equal(
    result.result.rememberHash,
    selectedRulesHash([...state.rules, rule('files.read', repo + '/another')], [selected]),
  );
  assert.notEqual(
    result.result.rememberHash,
    selectedRulesHash([...state.rules, { ...selected, mode: 'ask' }], [selected]),
  );
  const created = await gate(
    { ...request, resources: [worktree + '/services/finance/accountant/new/module.py'] },
    prepared,
  );
  assert.ok(
    created.candidates.some(
      (c) => c.target === worktree + '/services/finance/accountant' && c.targetType === 'directory',
    ),
  );
});
test('relevant rules, current instructions, and helper changes still invalidate review', async () => {
  const request = {
    action: 'edit',
    effect: 'ask',
    directory: repo,
    resources: [worktree + '/services/finance/accountant/file.py'],
    tool: { name: 'edit' },
  };
  const context = { users: [{ id: 'u', text: 'Edit the component.' }], delegation: [] };
  const p = { request, scope, config, permissions, state: { rules: [] } };
  const first = await gate(request, p);
  assert.equal(
    first.fingerprint,
    (await gate(request, { ...p, state: { rules: [rule('files.read', repo)] } })).fingerprint,
  );
  assert.notEqual(
    first.fingerprint,
    (await gate(request, { ...p, state: { rules: [rule('files.write', worktree, 'ask')] } }))
      .fingerprint,
  );
  const result = await reviewDynamic(p, {
    evidence: async () => structuredClone(context),
    refresh: async () => p,
    generate: async () => {
      context.users.push({ id: 'stop', text: 'Stop editing now.' });
      return { text: JSON.stringify({ decision: 'allow_once', reason: 'Edit.', remember: [] }) };
    },
  });
  assert.equal(result.result.code, 'review_context_changed');
});
test('classifier diagnostic reaches private audit with credentials redacted', async () => {
  const request = {
    action: 'edit',
    effect: 'ask',
    directory: repo,
    resources: [worktree + '/file'],
    tool: { name: 'edit' },
  };
  const p = { request, scope, config, permissions, state: { rules: [] } };
  const result = await reviewDynamic(p, {
    evidence: async () => ({ users: [], delegation: [] }),
    refresh: async () => p,
    generate: async () => {
      decodeDecisionResponse({
        choices: [
          {
            finish_reason: 'length',
            message: {
              content: 'API_KEY=fixture-secret',
              reasoning_content: 'hidden-model-thoughts',
              tool_calls: [],
            },
          },
        ],
      });
      throw Error('Expected decoder failure');
    },
  });
  assert.ok(result.diagnostics.failure.response, JSON.stringify(result));
  const logged = JSON.stringify(sanitizeAudit(result.diagnostics));
  assert.ok(logged.includes('length'));
  assert.ok(!logged.includes('fixture-secret'));
  assert.ok(!logged.includes('hidden-model-thoughts'));
});
test('safe environment prefixes and escaped regex literals retain exact argv', async () => {
  const request = shell(
    'set -euo pipefail; LC_ALL=C grep -n "alpha\\|beta" services/finance/accountant/file.py',
  );
  const result = await extractAction(request, { scope, config, runtime: host(request) });
  assert.equal(result.complete, true, JSON.stringify(result));
  assert.equal(result.commands[1].argv[2], 'alpha\\|beta');
  assert.deepEqual(result.commands[1].environment, { LC_ALL: 'C' });
  for (const command of [
    'PYTHONPATH=/tmp cat file',
    'LD_PRELOAD=/tmp/lib cat file',
    'PATH=/tmp cat file',
    'set -f; cat file',
    'set +e; cat file',
  ]) {
    const r = shell(command);
    assert.equal(
      (await extractAction(r, { scope, config, runtime: host(r) })).complete,
      false,
      command,
    );
  }
});
test('bounded globs expand targets and never execute substitutions or mutable globs', async () => {
  const directory = worktree + '/glob-fixture';
  await mkdir(directory);
  await writeFile(directory + '/one.txt', 'one');
  await writeFile(directory + '/two.txt', 'two');
  await mkdir(worktree + '/glob-output');
  for (const command of [
    'cat glob-fixture/*.txt',
    'cp glob-fixture/*.txt glob-output',
    'mkdir -p fresh/a fresh/b',
  ]) {
    const r = shell(command),
      a = await extractAction(r, { scope, config, runtime: host(r) });
    assert.equal(a.complete, true, JSON.stringify(a));
    if (command.startsWith('cp'))
      assert.ok(
        a.grants.some(
          (g) => g.operation === 'files.write' && g.target === worktree + '/glob-output/two.txt',
        ),
      );
  }
  for (const command of [
    'cat glob-fixture/**/*.txt',
    'cat glob-fixture/missing*.txt',
    'cat glob-fixture/$(echo one).txt',
    'cp glob-fixture/one.txt glob-fixture/new.txt; cat glob-fixture/*.txt',
  ]) {
    const r = shell(command);
    assert.equal(
      (await extractAction(r, { scope, config, runtime: host(r) })).complete,
      false,
      command,
    );
  }
  const r = shell('cat "glob-fixture/*.txt"'),
    a = await extractAction(r, { scope, config, runtime: host(r) });
  assert.equal(a.complete, false);
  assert.equal(a.commands[0].argv[1], 'glob-fixture/*.txt');
});
test('pytest prefix becomes a reusable test grant without approving arbitrary Python', async () => {
  await mkdir(worktree + '/tests/validation', { recursive: true });
  for (const tail of ['-2', '-4']) {
    const r = shell(
      'V=/usr/bin; PYTHONDONTWRITEBYTECODE=1 "$V/python3" -m pytest -q -p no:cacheprovider tests/validation 2>&1 | tail ' +
        tail,
    );
    const args = {
      scope,
      config,
      runtime: host(r),
      permissions,
      state: { rules: [rule('tests.run', worktree + '/tests')] },
    };
    const a = await gate(r, args);
    assert.equal(a.analysis.complete, true, JSON.stringify(a.analysis));
    assert.equal(a.decision, 'allow');
    assert.equal((await gate(r, { ...args, state: { rules: [] } })).decision, 'dynamic');
  }
  const r = shell('PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 helper.py');
  assert.equal(
    (
      await gate(r, {
        scope,
        config,
        runtime: host(r),
        permissions,
        state: { rules: [rule('tests.run', worktree)] },
      })
    ).decision,
    'dynamic',
  );
});
test('chained success paths bind variables while failure paths retain their own cwd', async () => {
  const r = shell(
    'cd services/finance/accountant && V=/usr/bin && PYTHONDONTWRITEBYTECODE=1 "$V/python3" -m pytest -q -p no:cacheprovider ../../../tests/validation 2>&1 | tail -2',
  );
  const a = await gate(r, {
    scope,
    config,
    runtime: host(r),
    permissions,
    state: { rules: [rule('files.access', worktree), rule('tests.run', worktree + '/tests')] },
  });
  assert.equal(a.analysis.complete, true, JSON.stringify(a.analysis));
  assert.equal(a.decision, 'allow');
  assert.ok(
    a.analysis.commands.some(
      (c) =>
        c.argv[0] === '/usr/bin/python3' && c.cwd === worktree + '/services/finance/accountant',
    ),
  );
  for (const command of [
    'cd services && cat success.txt || cat fallback.txt',
    'if cd services; then cat yes.txt; else cat no.txt; fi',
    'false | true && cat after.txt',
    'true > stream-output || cat fallback.txt',
  ]) {
    const r = shell(command),
      a = await extractAction(r, { scope, config, runtime: host(r) });
    assert.equal(a.complete, true, JSON.stringify(a));
    if (command.startsWith('cd'))
      assert.ok(a.grants.some((g) => g.target === worktree + '/fallback.txt'));
    if (command.startsWith('if'))
      assert.ok(a.grants.some((g) => g.target === worktree + '/no.txt'));
    if (command.startsWith('false'))
      assert.ok(a.grants.some((g) => g.target === worktree + '/after.txt'));
    if (command.startsWith('true'))
      assert.ok(a.grants.some((g) => g.target === worktree + '/fallback.txt'));
  }
});
test('native glob pattern maps to its directory rather than a literal pattern path', async () => {
  const request = {
    action: 'glob',
    effect: 'ask',
    directory: repo,
    resources: ['**/*.py'],
    tool: { name: 'glob', input: { pattern: '**/*.py', path: worktree + '/services' } },
  };
  const p = { scope, config, permissions, state: { rules: [rule('files.list', worktree)] } };
  const result = await gate(request, p);
  assert.equal(result.decision, 'allow');
  assert.equal(result.analysis.grants[0].target, worktree + '/services');
  assert.equal((await gate(request, { ...p, state: { rules: [] } })).decision, 'dynamic');
  const unsafe = {
    ...request,
    resources: ['../*'],
    tool: { name: 'glob', input: { pattern: '../*', path: worktree } },
  };
  assert.equal((await gate(unsafe, p)).decision, 'dynamic');
});
test('native grep binds the actual file or search directory, never the regex', async () => {
  await writeFile(base + '/.env', 'fixture only');
  await symlink(base + '/.env', repo + '/grep-link');
  const p = {
    scope,
    config,
    permissions,
    state: { rules: [rule('files.read', worktree), rule('files.list', worktree)] },
  };
  for (const pattern of ['needle', 'if x.*|F[1-9]']) {
    const r = {
      action: 'grep',
      effect: 'ask',
      directory: repo,
      resources: [pattern],
      tool: {
        name: 'grep',
        input: { pattern, path: worktree + '/services/finance/accountant/file.py' },
      },
    };
    const a = await gate(r, p);
    assert.equal(a.decision, 'allow');
    assert.equal(a.analysis.grants[0].target, r.tool.input.path);
    for (const file of [base + '/.env', repo + '/grep-link']) {
      const b = await gate({ ...r, tool: { name: 'grep', input: { pattern, path: file } } }, p);
      assert.equal(b.decision, 'dynamic');
      assert.equal(b.analysis.grants[0].operation, 'secrets.read');
    }
    assert.equal((await gate({ ...r, resources: ['other'] }, p)).decision, 'dynamic');
    const d = await gate(
      { ...r, tool: { name: 'grep', input: { pattern, path: worktree + '/services' } } },
      p,
    );
    assert.equal(d.decision, 'allow');
    assert.ok(
      d.analysis.grants.some(
        (g) =>
          g.operation === 'files.read' &&
          g.target === worktree + '/services/finance/accountant/file.py',
      ),
    );
  }
  await mkdir(repo + '/search');
  await writeFile(repo + '/search/.env', 'synthetic');
  assert.equal(
    (
      await gate(
        {
          action: 'grep',
          effect: 'ask',
          directory: repo,
          resources: ['needle'],
          tool: { name: 'grep', input: { pattern: 'needle', path: repo + '/search' } },
        },
        p,
      )
    ).decision,
    'dynamic',
  );
});
test('one directory listing grant resolves both native read stages without granting content reads', async () => {
  const r = {
    action: 'external_directory',
    effect: 'ask',
    directory: repo,
    resources: [worktree + '/*'],
    tool: { name: 'read', input: { path: worktree } },
  };
  const p = { scope, config, permissions, state: { rules: [rule('files.list', worktree)] } };
  for (const request of [r, { ...r, action: 'read', resources: [worktree] }])
    assert.equal((await gate(request, p)).decision, 'allow');
  assert.equal((await gate({ ...r, resources: [base + '/unrelated/*'] }, p)).decision, 'dynamic');
  const file = worktree + '/services/finance/accountant/file.py';
  assert.equal(
    (
      await gate(
        {
          ...r,
          resources: [pathParent(file) + '/*'],
          tool: { name: 'read', input: { path: file } },
        },
        p,
      )
    ).decision,
    'dynamic',
  );
});
function pathParent(file) {
  return file.slice(0, file.lastIndexOf('/'));
}
test('native read wildcard migration remains project-only and does not authorize secrets or writes', async () => {
  const store = createRuleStore(base + '/config/wildcard.json');
  const state = await store.import('read-all', [
    { id: 'read-all', projectID: 'read-all', action: 'read', resource: '*' },
  ]);
  for (const op of ['files.read', 'files.list'])
    assert.equal(
      resolveGrants([grant(op, worktree + '/services', 'directory')], state.rules).decision,
      'allow',
    );
  for (const op of ['secrets.read', 'files.write'])
    assert.equal(resolveGrants([grant(op, worktree + '/file')], state.rules).decision, 'dynamic');
  assert.deepEqual((await store.read('different')).rules, []);
  await store.set('read-all', grant('files.read', worktree, 'directory'), 'ask');
  const again = await store.import('read-all', [
    { id: 'read-all', projectID: 'read-all', action: 'read', resource: '*' },
  ]);
  assert.equal(
    resolveGrants([grant('files.read', worktree + '/file')], again.rules).decision,
    'ask',
  );
});

test('grep context options preserve file targets and reject unsupported flag payloads', async () => {
  for (const flag of ['-A5', '-B10', '-C0', '-A 5', '-B 10', '-C 2']) {
    const r = shell('cat services/finance/accountant/file.py | grep ' + flag + ' fixture');
    const a = await extractAction(r, { scope, config, runtime: host(r) });
    assert.equal(a.complete, true, JSON.stringify(a));
  }
  for (const flag of ['-A', '-Bfile', '-C-1', '-A999999999', '--include=*.py', '-f pattern']) {
    const r = shell('grep ' + flag + ' fixture services/finance/accountant/file.py');
    assert.equal(
      (await extractAction(r, { scope, config, runtime: host(r) })).complete,
      false,
      flag,
    );
  }
});
test('scratch reports may accompany Git reads, but writes to Git configuration cannot', async () => {
  await mkdir(scope.scratch, { recursive: true });
  const r = shell('printf fixture > ' + scope.scratch + '/report.txt; git status --short');
  const a = await gate(r, {
    scope,
    config,
    runtime: host(r),
    permissions,
    state: { rules: [rule('git.read', worktree)] },
  });
  assert.equal(a.analysis.complete, true, JSON.stringify(a.analysis));
  assert.equal(a.decision, 'allow');
  const unsafe = shell('printf fixture > .git/config; git status --short');
  assert.equal(
    (await extractAction(unsafe, { scope, config, runtime: host(unsafe) })).complete,
    false,
  );
});
test('model context keeps the command and evidence but excludes the raw shell AST', async () => {
  const r = shell('unknown-fixture-command'),
    p = { request: r, scope, config, runtime: host(r), permissions, state: { rules: [] } };
  let data;
  const result = await reviewDynamic(p, {
    evidence: async () => ({ users: [{ id: 'u', text: 'Inspect this fixture.' }], delegation: [] }),
    refresh: async () => p,
    generate: async (input) => {
      data = JSON.parse(input.prompt.split('\n').at(-1));
      return {
        text: JSON.stringify({
          decision: 'escalate_once',
          reason: 'Unknown effects.',
          remember: [],
        }),
      };
    },
  });
  assert.ok(result.diagnostics.static.analysis.syntax);
  assert.equal(data.analysis.syntax, undefined);
  assert.equal(data.analysis.snapshots, undefined);
  assert.equal(data.request.tool.input.command, r.tool.input.command);
  assert.equal(data.users[0].text, 'Inspect this fixture.');
});

test('Git config inputs inside scratch and repository writes still require full review', async () => {
  const directory = base + '/git-guard',
    scratch = directory + '/scratch',
    root = directory + '/repo';
  await mkdir(scratch, { recursive: true });
  await mkdir(root);
  execFileSync('/usr/bin/git', ['init', '-q', root]);
  const conf = scratch + '/included.cfg';
  await writeFile(conf, '[core]\n  bare = false\n');
  execFileSync('/usr/bin/git', ['-C', root, 'config', 'include.path', conf]);
  const inspect = async (filename) => {
    const r = shell('printf fixture > ' + filename + '; git status --short');
    r.tool.input.workdir = root;
    return extractAction(r, {
      scope: { ...scope, scratch },
      config,
      runtime: { ...host(r), cwd: root },
    });
  };
  assert.equal((await inspect(scratch + '/report.txt')).complete, true);
  for (const filename of [conf, root + '/file', root + '/.git/config']) {
    const a = await inspect(filename);
    assert.equal(a.complete, false, filename);
    assert.equal(a.reason, 'authority_modified_in_command');
  }
  await symlink(root + '/.git/config', scratch + '/link');
  assert.equal((await inspect(scratch + '/link')).complete, false);
  await link(root + '/.git/config', scratch + '/hardlink');
  assert.equal((await inspect(scratch + '/hardlink')).complete, false);
  execFileSync('/usr/bin/git', ['-C', root, 'config', 'include.path', scratch + '/missing.cfg']);
  assert.equal((await inspect(scratch + '/missing.cfg')).complete, false);
});
test('Git status literal pathspecs retain boundaries and reject magic or escaping paths', async () => {
  const r = shell(
    'git --no-pager status --short --untracked-files=all -- services/finance/accountant',
  );
  assert.equal(
    (
      await gate(r, {
        scope,
        config,
        runtime: host(r),
        permissions,
        state: { rules: [rule('git.read', worktree), rule('files.list', worktree)] },
      })
    ).decision,
    'allow',
  );
  for (const p of [':(top)services', '../outside', 'services/*', '--untracked-files=no']) {
    const r = shell("git status --short -- '" + p + "'");
    assert.equal((await extractAction(r, { scope, config, runtime: host(r) })).complete, false, p);
  }
});
test('SQLite safe inspection uses the database read grant and rejects side-effect syntax', async () => {
  const file = worktree + '/data.db';
  execFileSync('/usr/bin/sqlite3', [file, 'CREATE TABLE data (id TEXT);']);
  for (const sql of ['.tables', '.schema data', 'SELECT id FROM data LIMIT 10']) {
    const r = shell("sqlite3 -safe -readonly -init /dev/null '" + file + "' '" + sql + "'");
    const a = await gate(r, {
      scope,
      config,
      runtime: host(r),
      permissions,
      state: { rules: [rule('files.read', worktree)] },
    });
    assert.equal(a.decision, 'allow', JSON.stringify(a.analysis));
    assert.equal(a.analysis.commands[0].sqlite.safeMode, true);
    assert.ok(a.analysis.grants.some((g) => g.operation === 'files.read' && g.target === file));
  }
});
test('jq identity formatting preserves file grants and rejects programs or argument loaders', async () => {
  const bin = base + '/jq';
  await copyFile('/usr/bin/true', bin);
  await chmod(bin, 0o755);
  const file = worktree + '/fixture.json';
  await writeFile(file, '{}');
  const cfg = {
    ...config,
    staticShell: {
      ...config.staticShell,
      executables: [{ name: 'jq', path: bin, realpath: bin, sha256: sha256(await readFile(bin)) }],
    },
  };
  const inspect = async (command) => {
    const r = shell(command);
    return gate(r, {
      scope,
      config: cfg,
      runtime: host(r),
      permissions,
      state: { rules: [rule('files.read', worktree)] },
    });
  };
  for (const command of [`${bin} -rS . '${file}'`, `cat '${file}' | ${bin} .`]) {
    const a = await inspect(command);
    assert.equal(a.decision, 'allow', JSON.stringify(a.analysis));
    assert.ok(a.analysis.grants.some((g) => g.operation === 'files.read' && g.target === file));
  }
  await writeFile(worktree + '/.env', 'fixture-only');
  const secret = await inspect(`${bin} . '${worktree}/.env'`);
  assert.equal(secret.decision, 'dynamic');
  assert.ok(secret.analysis.grants.some((g) => g.operation === 'secrets.read'));
  for (const args of [
    '--rawfile x /etc/passwd .',
    '--from-file filter.jq',
    '--arg x value .',
    '-n .',
    '.field',
    '.',
    '\'import "module"; .\'',
    '. -- file',
  ]) {
    const a = await inspect(`${bin} ${args}`);
    assert.equal(a.analysis.complete, false, args);
    assert.equal(a.decision, 'dynamic', args);
  }
});
test('literal command arrays normalize Beads operation and repository without interpreter wildcards', async () => {
  const root = base + '/beads-array',
    bin = base + '/bd';
  await mkdir(root + '/.beads/embeddeddolt', { recursive: true });
  await writeFile(
    root + '/.beads/metadata.json',
    JSON.stringify({
      backend: 'dolt',
      dolt_mode: 'embedded',
      database: 'dolt',
      dolt_database: 'fixture',
    }),
  );
  await writeFile(root + '/.beads/config.yaml', 'dolt.local-only: true\n');
  // Pinned inert fixture binary: extraction never executes Beads.
  await copyFile('/usr/bin/true', bin);
  await chmod(bin, 0o755);
  const cfg = {
    ...config,
    staticShell: {
      ...config.staticShell,
      executables: [{ name: 'bd', path: bin, realpath: bin, sha256: sha256(await readFile(bin)) }],
    },
  };
  const command = `P='${root}'; BD=(${sandboxWrapper}'${bin}' --sandbox --dolt-auto-commit off -C "$P"); "\${BD[@]}" update fixture --status in_progress`;
  const r = shell(command),
    p = {
      scope,
      config: cfg,
      runtime: host(r),
      permissions,
      state: { rules: [rule('beads.update', root)] },
    };
  const a = await gate(r, p);
  assert.equal(a.decision, 'allow', JSON.stringify(a.analysis));
  assert.ok(a.analysis.grants.some((g) => g.operation === 'beads.update' && g.target === root));
  assert.equal(
    (await gate(r, { ...p, scope: { ...scope, agent: 'oracle', readOnly: true } })).decision,
    'ask',
  );
  for (const suffix of [
    '"${BD[*]}" update x',
    '${BD[@]} update x',
    'BD[0]=other; "${BD[@]}" update x',
    'BD+=(-bad); "${BD[@]}" update x',
    'BD=other; "${BD[@]}" update x',
    'for BD in other; do "${BD[@]}" update x; done',
  ]) {
    const q = shell(command.slice(0, command.indexOf('; "${BD[@]}"')) + '; ' + suffix);
    assert.equal(
      (await extractAction(q, { scope, config: cfg, runtime: host(q) })).complete,
      false,
      suffix,
    );
  }
});
