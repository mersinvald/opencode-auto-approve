import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { globalRules, nativeRestriction } from './grant-gate.mjs';
import { grant, resolveGrants } from './grant-rules.mjs';

const scope = {
  directory: '/work/app',
  scratch: '/scratch/child',
  readableAncestorScratch: ['/scratch/parent'],
  agent: 'orchestrator',
};
const config = { skillRoots: ['/skills'], protectedRoots: [], staticShell: {} };
const rules = globalRules(config, scope);
const decision = (items, policy = rules) => resolveGrants(items, policy).decision;

test('starter scopes allow child reads and own scratch writes without trusting siblings', () => {
  assert.equal(
    decision([
      grant('files.read', '/work/app/src/file.ts'),
      grant('git.read', '/work/app', 'directory'),
      grant('files.read', '/scratch/parent/report.md'),
      grant('files.read', '/skills/writer/SKILL.md'),
      grant('files.write', '/scratch/child/report.md'),
      grant('files.delete', '/scratch/child/old.log'),
    ]),
    'allow',
  );
  for (const item of [
    grant('files.read', '/work/app-backup/file.ts'),
    grant('files.write', '/work/app/src/file.ts'),
    grant('files.write', '/scratch/parent/report.md'),
    grant('files.write', '/skills/writer/SKILL.md'),
    grant('secrets.read', '/work/app/.env'),
    grant('shell.opaque', 'python3 arbitrary.py', 'exact'),
  ])
    assert.equal(decision([item]), 'dynamic', item.operation + ': ' + item.target);
});

test('read permission does not resolve extra effects or override an explicit project ask', () => {
  const read = grant('files.read', '/work/app/src/file.ts');
  assert.equal(decision([read, grant('secrets.read', '/work/app/.env')]), 'dynamic');
  assert.equal(
    decision(
      [read],
      [
        ...rules,
        {
          operation: 'files.read',
          target: '/work/app/src',
          targetType: 'directory',
          mode: 'ask',
          scope: 'project',
          authority: 'user',
        },
      ],
    ),
    'ask',
  );
});

const shared = JSON.parse(
  await readFile(new URL('./examples/shared-repository.json', import.meta.url)),
);
const development = JSON.parse(
  await readFile(new URL('./examples/component-development.json', import.meta.url)),
);

test('shared repository example grants reads without mutations or interpreter wildcards', () => {
  const policy = globalRules({ ...config, ...shared }, scope);
  const root = '/path/to/shared-repository';
  assert.equal(
    decision(
      [
        grant('files.read', root + '/docs/guide.md'),
        grant('files.list', root + '/src', 'directory'),
        grant('git.read', root, 'directory'),
      ],
      policy,
    ),
    'allow',
  );
  for (const item of [
    grant('files.read', root + '-other/guide.md'),
    grant('files.write', root + '/src/file.ts'),
    grant('files.delete', root + '/src/file.ts'),
    grant('beads.update', root, 'directory'),
    grant('shell.opaque', 'python3 *', 'exact'),
  ])
    assert.equal(decision([item], policy), 'dynamic', item.operation);
});

test('component example bounds edits and tests, and retains Beads role and native deny checks', () => {
  const settings = { ...config, ...development };
  const policy = globalRules(settings, scope);
  const root = '/path/to/repository';
  const update = grant('beads.update', root, 'directory');
  assert.equal(
    decision(
      [
        grant('files.write', root + '/src/file.ts'),
        grant('files.write', root + '/tests/test_checkout.py'),
        grant('tests.run', root + '/tests/test_checkout.py'),
        update,
      ],
      policy,
    ),
    'allow',
  );
  for (const item of [
    grant('files.write', root + '/README.md'),
    grant('files.write', root + '/src-backup/file.ts'),
    grant('tests.run', root + '/scripts/admin.py'),
    grant('beads.manage', root + '-other', 'directory'),
    grant('files.delete', root + '/src/file.ts'),
    grant('policy.write', root + '/src/AGENTS.md'),
    grant('secrets.read', root + '/src/.env'),
    grant('git.push', root, 'directory'),
  ])
    assert.equal(decision([item], policy), 'dynamic', item.operation + ': ' + item.target);
  const request = { action: 'shell', resources: ['bd update issue'], effect: 'ask' };
  const analysis = { grants: [update], commands: [] };
  assert.equal(nativeRestriction(request, analysis, {}, scope, settings), null);
  assert.match(
    nativeRestriction(request, analysis, {}, { ...scope, agent: 'worker' }, settings),
    /writer roles/,
  );
  assert.match(
    nativeRestriction(request, analysis, {}, { ...scope, readOnly: true }, settings),
    /may not write/,
  );
  assert.equal(
    nativeRestriction({ ...request, effect: 'deny' }, analysis, {}, scope, settings),
    'Native deny rule',
  );
});
