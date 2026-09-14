import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, symlink, unlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonical } from './policy.mjs';
import { scriptEvidence } from './review-context.mjs';
import { helperReferences } from './shell-context.mjs';

const root = await canonical(await mkdtemp(path.join(os.tmpdir(), 'approval-shell-')), '/');
const skill = path.join(root, 'skills');
await mkdir(skill);
const config = {
  version: 1,
  mode: 'enforce',
  model: { providerID: 'fixture', id: 'model', variant: 'medium' },
  skillRoots: [skill],
  protectedRoots: [root + '/policy.json'],
  scratchRoot: root + '/scratch',
  auditRoot: root + '/audit',
  timeoutMs: 500,
  maxRequestChars: 32000,
};
const scope = { directory: root, scratch: root + '/scratch' };
const request = (command) => ({
  action: 'shell',
  resources: [command],
  effect: 'ask',
  tool: { name: 'shell', input: { command, workdir: root } },
  directory: root,
});
const decision = {
  effect: 'allow',
  consequence: 'local_execution',
  inScope: true,
  authorization: 'task',
  evidence: null,
  reason: 'Authorized documentation checks with a scratch report.',
};
const proof = {
  users: [{ id: 'msg_user', text: 'Migrate workflow documents in the affected repositories.' }],
  delegation: [],
  scope,
};

test('output paths are not pre-existing helper inputs', async () => {
  const target = root + '/new-output.py';
  assert.deepEqual(helperReferences(`cat > ${target} <<'PY'\nprint('new')\nPY`), []);
  assert.deepEqual(await scriptEvidence(request(`echo data > ${target}`).tool, scope, config), []);
});

test('pytest test selection is not a literal helper path', async () => {
  for (const command of [
    'PYTHONDONTWRITEBYTECODE=1 /fixture/venv/bin/python -m pytest -q -p no:cacheprovider tests/validation/test_phase1_*.py',
    'python3 -I -B -m pytest /fixture/test_*.py',
    'python3 -m pytest tests/test_one.py tests/test_two.py tests/test_three.py tests/test_four.py',
  ]) {
    assert.deepEqual(helperReferences(command), [], command);
    assert.deepEqual(await scriptEvidence(request(command).tool, scope, config), [], command);
  }
  assert.deepEqual(helperReferences('python3 /fixture/test_*.py'), ['/fixture/test_*.py']);
  await assert.rejects(
    scriptEvidence(request('python3 /fixture/test_*.py').tool, scope, config),
    /Unresolved path pattern/,
  );
  assert.deepEqual(helperReferences('python3 runner.py -m pytest'), ['runner.py']);
  assert.deepEqual(
    helperReferences('python3 -m pytest tests/test_*.py; python3 /fixture/helper.py'),
    ['/fixture/helper.py'],
  );
});
