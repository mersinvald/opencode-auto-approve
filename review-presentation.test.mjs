import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  compactResolvedGrants,
  groupDiagnostics,
  reviewPresentation,
} from './review-presentation.mjs';
import { grant } from './grant-rules.mjs';
import { reviewPrompt } from './grant-decision.mjs';

const space = { repository: 'a'.repeat(64), modifier: 'scratch' };
function atom(target, extra = {}) {
  return {
    ...grant('tests.run', target, 'file', { space }),
    mode: 'allow',
    repositoryName: 'infra',
    physicalTarget: '/worktrees/infra/one/' + target,
    rule: {
      operation: 'tests.run',
      target: '*',
      targetType: 'any',
      mode: 'allow',
      authority: 'model',
    },
    ...extra,
  };
}

test('focus contains only pending IDs; compact allow targets stay exact', () => {
  const pending = {
    ...grant('files.delete', '/scratch/pytest', 'directory'),
    mode: 'dynamic',
    rule: null,
  };
  const data = {
    grants: [atom('tests/a.py'), atom('tests/b.py'), pending],
    candidates: [pending],
    analysis: { complete: true, unresolved: [] },
  };
  const original = structuredClone(data),
    p = reviewPresentation(data);
  assert.deepEqual(data, original);
  assert.deepEqual(p.reviewFocus, {
    pendingGrantIDs: [pending.id],
    parserCoverageIncomplete: false,
    resolvedGrantCount: 2,
  });
  assert.deepEqual(p.grants, [pending]);
  assert.deepEqual(p.candidates, data.candidates);
  assert.equal(p.resolvedGrants.length, 1);
  const g = p.resolvedGrants[0];
  assert.equal(g.targetType, 'file');
  assert.deepEqual(g.targets, [{ target: 'tests/a.py' }, { target: 'tests/b.py' }]);
  assert.equal(g.physicalRoot, '/worktrees/infra/one');
  assert.ok(!Object.hasOwn(g, 'id') && !Object.hasOwn(g, 'rule'));
});

test('resolved groups never merge repositories, worktrees, scopes, operations, or target types', () => {
  const items = [
    atom('tests/a.py'),
    atom('tests/b.py'),
    atom('tests/a.py', { space: { ...space, repository: 'b'.repeat(64) } }),
    atom('tests/a.py', { physicalTarget: '/worktrees/infra/two/tests/a.py' }),
    atom('tests/a.py', { space: undefined, target: '/main/tests/a.py', physicalTarget: undefined }),
    atom('tests/a.py', { operation: 'files.read' }),
    atom('tests/a.py', { targetType: 'directory' }),
  ];
  const groups = compactResolvedGrants(items);
  assert.equal(groups.length, 6);
  const expanded = groups.flatMap(({ targets, physicalRoot, ...common }) =>
    targets.map(({ target, physicalTarget }) => ({
      ...common,
      target,
      ...(physicalRoot || physicalTarget
        ? { physicalTarget: physicalTarget ?? path.posix.join(physicalRoot, target) }
        : {}),
    })),
  );
  assert.deepEqual(
    expanded,
    items.map(({ id, rule, ...item }) => {
      if (item.physicalTarget === undefined) delete item.physicalTarget;
      return item;
    }),
  );
});

test('physical target factoring preserves root, dot, and nonmatching paths', () => {
  for (const [target, physicalTarget, expectedRoot] of [
    ['.', '/worktrees/one', '/worktrees/one'],
    ['file', '/file', '/'],
    ['src/file', '/unrelated/file', undefined],
    ['../file', '/worktrees/file', undefined],
  ]) {
    const g = compactResolvedGrants([atom('valid', { target, physicalTarget })])[0];
    assert.equal(g.physicalRoot, expectedRoot);
    assert.equal(g.targets[0].physicalTarget, expectedRoot ? undefined : physicalTarget);
  }
});

test('grouped diagnostics retain every location, duplicate count, and semantic field', () => {
  const one = {
    reason: 'python_unknown_callable',
    source: '<inline>',
    commandIndex: 0,
    line: 3,
    column: 0,
    endLine: 4,
  };
  const two = { ...one, commandIndex: 2, line: 9, endLine: 9 };
  const input = [
    one,
    { ...one },
    two,
    { ...two, cwd: '/other', branches: [{ outcome: 'failure' }] },
  ];
  const out = groupDiagnostics(input);
  assert.equal(out.length, 2);
  assert.equal(out[0].occurrences, 3);
  assert.deepEqual(out[0].locations, [
    { commandIndex: 0, line: 3, column: 0, endLine: 4, count: 2 },
    { commandIndex: 2, line: 9, column: 0, endLine: 9 },
  ]);
  assert.deepEqual(out[1], input[3]);
  const expanded = out.flatMap((g) => {
    if (!g.locations) return [g];
    const { locations, occurrences, ...detail } = g;
    return locations.flatMap(({ count = 1, ...location }) =>
      Array.from({ length: count }, () => ({ ...detail, ...location })),
    );
  });
  assert.deepEqual(expanded, input);
});

test('different targets, branch outcomes, sources, and future fields remain distinct', () => {
  const base = {
    reason: 'missing',
    commandIndex: 0,
    cwd: '/old',
    target: '/old/test.py',
    source: 'one.py',
  };
  const input = [
    base,
    { ...base, cwd: '/new' },
    { ...base, target: '/new/test.py' },
    { ...base, source: 'two.py' },
    { ...base, branches: [{ outcome: 'failure' }] },
    { ...base, branches: [{ outcome: 'success' }] },
    { ...base, futureEvidence: 'keep' },
  ];
  assert.deepEqual(groupDiagnostics(input), input);
  assert.deepEqual(groupDiagnostics([{ reason: 'x' }, { reason: 'x' }]), [
    { reason: 'x', occurrences: 2, locations: [{ count: 2 }] },
  ]);
});

test('full source, authority, restrictions, and incomplete coverage survive presentation', () => {
  const data = {
    users: [{ id: 'u', text: 'Do not delete data.' }],
    delegation: [{ text: 'Read the fixture.' }],
    request: {
      tool: { input: { command: 'python3 helper.py' } },
      scripts: [{ path: 'helper.py', text: "import shutil; shutil.rmtree('/user-data')" }],
    },
    analysis: { complete: false, unresolved: [{ reason: 'python_source', commandIndex: 0 }] },
    grants: [atom('tests/a.py')],
    candidates: [],
    nativeRestrictions: { readOnly: true, deny: ['files.delete'] },
  };
  const p = JSON.parse(reviewPrompt(data).split('\n').at(-1));
  assert.equal(p.reviewFocus.parserCoverageIncomplete, true);
  assert.deepEqual(p.reviewFocus.pendingGrantIDs, []);
  for (const k of [
    'users',
    'delegation',
    'request',
    'nativeRestrictions',
    'analysis',
    'candidates',
  ])
    assert.deepEqual(p[k], data[k]);
  assert.deepEqual(p.allowedDecisions, ['allow_once', 'escalate_once']);
});

test('ask and unrecognized modes are never hidden among resolved permissions', () => {
  const items = [atom('a', { mode: 'ask' }), atom('b', { mode: 'future' })];
  const p = reviewPresentation({ grants: items });
  assert.deepEqual(p.grants, items);
  assert.deepEqual(p.resolvedGrants, []);
  assert.equal(p.reviewFocus.parserCoverageIncomplete, true);
});

test('path diagnostics discard only exact duplicates', () => {
  const a = { lexical: '/a', resolved: '/b' },
    b = { lexical: '/a', resolved: '/c' };
  assert.deepEqual(
    reviewPresentation({ analysis: { pathResolutions: [a, { ...a }, b] } }).analysis
      .pathResolutions,
    [a, b],
  );
});
