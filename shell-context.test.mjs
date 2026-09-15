import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtemp,
  mkdir,
  writeFile,
  symlink,
  unlink,
  copyFile,
  readFile,
  realpath,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonical } from './policy.mjs';
import { scriptEvidence } from './review-context.mjs';
import { helperReferences } from './shell-context.mjs';
import { sha256 } from './shell-host.mjs';

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

test('verified isolated lint inputs are data, even when they are large Python files', async () => {
  const python = root + '/python3',
    lint = root + '/lint.py';
  await copyFile('/usr/bin/true', python);
  await writeFile(lint, "print('fixture linter')\n");
  const pin = async (file) => ({
    path: file,
    realpath: await realpath(file),
    sha256: sha256(await readFile(file)),
  });
  const settings = {
    ...config,
    staticShell: {
      helpers: [await pin(lint)],
      executables: [{ name: 'python3', ...(await pin(python)) }],
    },
  };
  const inputs = [];
  for (let i = 0; i < 4; i++) {
    const file = root + '/lint-input-' + i + '.py';
    await writeFile(file, '# data only\n'.repeat(4000));
    inputs.push(file);
  }
  const command = `${python} -I -S -B ${lint} ${inputs.join(' ')} 2>&1 | tail -20`;
  const scripts = await scriptEvidence(request(command).tool, scope, settings);
  assert.deepEqual(
    scripts.map((s) => s.path),
    [lint],
  );
  assert.equal(scripts[0].text, await readFile(lint, 'utf8'));
  const tooLarge = (error) => error.approvalCode === 'helper_source_too_large';
  await assert.rejects(
    scriptEvidence(request(command.replace('-I -S -B ', '')).tool, scope, settings),
    tooLarge,
  );
  for (const type of ['helpers', 'executables']) {
    const changed = structuredClone(settings);
    changed.staticShell[type][0].sha256 = '0'.repeat(64);
    await assert.rejects(scriptEvidence(request(command).tool, scope, changed), tooLarge);
  }
  const other = root + '/unknown.py';
  await writeFile(other, "print('unverified runner')\n");
  await assert.rejects(
    scriptEvidence(request(command.replace(lint, other)).tool, scope, settings),
    tooLarge,
  );
  // The source budget still applies to an actual unverified helper.
  await assert.rejects(
    scriptEvidence(request(`${python} -I -S -B ${inputs[0]}`).tool, scope, settings),
    tooLarge,
  );
});

test('bare Python lint discovery uses the exact captured shell PATH and workdir', async () => {
  const bin = root + '/pinned-bin',
    workdir = root + '/external-worktree',
    lint = root + '/bare-lint.py';
  await mkdir(bin);
  await mkdir(workdir);
  await copyFile('/usr/bin/true', bin + '/python3');
  await writeFile(lint, "print('fixture linter')\n");
  await writeFile(workdir + '/input.py', '# data only\n'.repeat(4000));
  const pin = async (file) => ({
    path: file,
    realpath: await realpath(file),
    sha256: sha256(await readFile(file)),
  });
  const settings = {
    ...config,
    staticShell: {
      helpers: [await pin(lint)],
      executables: [{ name: 'python3', ...(await pin(bin + '/python3')) }],
    },
  };
  const command = `python3 -I -S -B '${lint}' 'input.py'`;
  const tool = { name: 'shell', input: { command, workdir } };
  const runtime = {
    command,
    cwd: workdir,
    shell: '/bin/bash',
    env: { PATH: bin + ':/usr/bin:/bin' },
  };
  assert.deepEqual(
    (await scriptEvidence(tool, scope, settings, [], { runtime })).map((s) => s.path),
    [lint],
  );
  const tooLarge = (error) => error.approvalCode === 'helper_source_too_large';
  for (const untrusted of [
    undefined,
    { ...runtime, command: command + ' ' },
    { ...runtime, cwd: root },
    { ...runtime, shell: '/unverified/shell' },
    { ...runtime, env: { PATH: '.:' + bin } },
    { ...runtime, env: { ...runtime.env, BASH_ENV: '/unverified/startup' } },
  ]) {
    await assert.rejects(
      scriptEvidence(tool, scope, settings, [], { runtime: untrusted }),
      tooLarge,
    );
  }
  // A PATH shadow must stop resolution; never skip it to reach a trusted Python.
  const shadow = root + '/shadow';
  await mkdir(shadow);
  await writeFile(shadow + '/python3', '#!/bin/sh\nexit 0\n', { mode: 0o700 });
  await assert.rejects(
    scriptEvidence(tool, scope, settings, [], {
      runtime: { ...runtime, env: { PATH: shadow + ':' + runtime.env.PATH } },
    }),
    tooLarge,
  );
  for (const kind of ['helpers', 'executables']) {
    const changed = structuredClone(settings);
    changed.staticShell[kind][0].sha256 = '0'.repeat(64);
    await assert.rejects(scriptEvidence(tool, scope, changed, [], { runtime }), tooLarge);
  }
  const compound = `cd '${workdir}' && python3 -ISB '${lint}' '${workdir}/input.py' 2>&1 | tail -20`;
  assert.deepEqual(
    (
      await scriptEvidence(
        { ...tool, input: { command: compound, workdir } },
        scope,
        settings,
        [],
        {
          runtime: { ...runtime, command: compound },
        },
      )
    ).map((s) => s.path),
    [lint],
  );
  for (const prefix of [`PATH='${bin}' `, `export PATH='${bin}'; `, 'echo ready; ']) {
    const changed = prefix + `python3 -ISB '${lint}' '${workdir}/input.py'`;
    await assert.rejects(
      scriptEvidence({ ...tool, input: { command: changed, workdir } }, scope, settings, [], {
        runtime: { ...runtime, command: changed },
      }),
      tooLarge,
    );
  }
  // Identity evidence for the first invocation cannot classify later invocations.
  const repeated = `python3 -ISB '${lint}'; export PATH='${shadow}'; python3 -ISB '${lint}' '${workdir}/input.py'`;
  await assert.rejects(
    scriptEvidence({ ...tool, input: { command: repeated, workdir } }, scope, settings, [], {
      runtime: { ...runtime, command: repeated },
    }),
    tooLarge,
  );
});

test('native directory access does not prepare sources for the later shell action', async () => {
  const tool = request(`python3 -I -S -B '${root}/missing-directory-helper.py'`).tool;
  const diagnostics = [];
  assert.deepEqual(
    await scriptEvidence(tool, scope, config, diagnostics, { action: 'external_directory' }),
    [],
  );
  assert.deepEqual(diagnostics, []);
  await assert.rejects(
    scriptEvidence(tool, scope, config, [], { action: 'shell' }),
    (error) => error.approvalCode === 'helper_source_unavailable',
  );
});
