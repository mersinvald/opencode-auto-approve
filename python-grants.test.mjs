import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, mkdir, symlink, realpath } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gate } from './grant-gate.mjs';
import { grantDescriptor } from './grant-rules.mjs';
import { sha256 } from './shell-host.mjs';
import { grantSnapshot } from './audit-grants.mjs';

const root = await mkdtemp(realpathSync(tmpdir()) + '/python-grants-');
const repo = fileURLToPath(new URL('.', import.meta.url));
const profileFile = root + '/profile.json';
execFileSync('python3', ['-I', '-S', '-B', repo + 'build_python.py', '--output', profileFile]);
const python = JSON.parse(await readFile(profileFile, 'utf8'));
const exe = python.environments[0].interpreter.path;
const shellParser = repo + 'bin/shell-parser';
const config = {
  skillRoots: [],
  protectedRoots: [],
  staticPython: python,
  staticShell: {
    enabled: true,
    parser: { path: shellParser, sha256: sha256(await readFile(shellParser)) },
    executables: [{ ...python.environments[0].interpreter, name: path.basename(exe) }],
  },
};
const scope = { directory: root, agent: 'orchestrator' };
const permissions = { projectID: 'python-fixture', saved: [], sessions: [], agent: { rules: [] } };
await writeFile(root + '/input', 'fixture');
const quote = (s) => "'" + s.replaceAll("'", "'\\''") + "'";
const commandFor = (body, flags = '-I -S -B') => `${quote(exe)} ${flags} - <<'PY'\n${body}\nPY`;
const inspect = (command, rules = [], extra = {}) =>
  gate(
    {
      action: 'shell',
      effect: 'ask',
      directory: root,
      resources: [command],
      tool: { name: 'shell', input: { command } },
    },
    {
      scope,
      config,
      permissions,
      state: { rules },
      runtime: { command, cwd: root, shell: '/bin/bash', env: { PATH: '/usr/bin:/bin' } },
      ...extra,
    },
  );
const allow = (grant) => ({
  ...grantDescriptor(grant),
  mode: 'allow',
  scope: 'project',
  authority: 'user',
});

test('Python imports and file calls require independent atomic rules', async () => {
  const command = commandFor(
    "from pathlib import Path\nPath('input').read_text()\nPath('out').write_text('ok')",
  );
  const first = await inspect(command);
  assert.equal(first.analysis.complete, true, JSON.stringify(first.analysis.unresolved));
  assert.equal(first.decision, 'dynamic');
  const imports = first.analysis.grants.filter((g) => g.operation === 'python.import');
  assert.deepEqual(
    imports.map((g) => g.target),
    ['pathlib'],
  );
  assert.equal((await inspect(command, imports.map(allow))).decision, 'dynamic');
  const rules = first.analysis.grants.map(allow);
  assert.equal((await inspect(command, rules)).decision, 'allow');
  const ask = {
    ...allow(first.analysis.grants.find((g) => g.operation === 'files.write')),
    mode: 'ask',
  };
  assert.equal(
    (await inspect(command, [...rules.filter((r) => r.operation !== 'files.write'), ask])).decision,
    'ask',
  );
  assert.equal(
    grantSnapshot(first).entries.find((e) => e.grant.operation === 'files.write').grant.locations[0]
      .line,
    3,
  );
});

test('os imports add no import grant and Python functions flow through file rules', async () => {
  const command = commandFor(
    "import os\ndef read(name):\n    return open(name).read()\nfor name in ['input']:\n    read(name)",
  );
  const result = await inspect(command);
  assert.equal(result.analysis.complete, true, JSON.stringify(result.analysis.unresolved));
  assert.equal(result.decision, 'allow');
  assert.equal(
    result.analysis.grants.some((g) => g.operation === 'python.import'),
    false,
  );
});

test('Python subprocess argv and POSIX shell source share the shell effect adapters', async () => {
  const command = commandFor(
    "import subprocess\nsubprocess.run(['/usr/bin/sed','-n','1p','input'])\nsubprocess.run('cat input | wc -l',shell=True)",
  );
  const result = await inspect(command);
  assert.equal(result.analysis.complete, true, JSON.stringify(result.analysis.unresolved));
  assert.ok(result.analysis.commands.some((c) => c.argv[0] === '/usr/bin/sed'));
  assert.equal((await inspect(command, result.analysis.grants.map(allow))).decision, 'allow');
  const unsupported = await inspect(
    commandFor("import subprocess\nsubprocess.run('[[ -f input ]]',shell=True)"),
  );
  assert.equal(unsupported.analysis.complete, false);
});

test('unverified startup, helper changes and unknown library code cannot obtain a static allow', async () => {
  const normal = await inspect(commandFor("open('input').read()", '-B'));
  assert.ok(normal.analysis.grants.some((g) => g.operation === 'python.startup'));
  assert.equal(normal.analysis.complete, false);
  assert.equal(
    (await inspect(commandFor("open('input').read()", '-B'), normal.analysis.grants.map(allow)))
      .decision,
    'dynamic',
  );
  const helper = root + '/helper.py';
  await writeFile(helper, "open('input').read()\n");
  const first = await inspect(`${quote(exe)} -I -S -B ${quote(helper)}`);
  assert.equal(first.analysis.complete, true, JSON.stringify(first.analysis.unresolved));
  await writeFile(helper, "eval(open('input').read())\n");
  const second = await inspect(`${quote(exe)} -I -S -B ${quote(helper)}`);
  assert.equal(second.analysis.complete, false);
  assert.notEqual(first.fingerprint, second.fingerprint);
  const unknown = await inspect(commandFor('import nonexistent_fixture_module'));
  assert.equal(unknown.analysis.complete, false);
  assert.ok(unknown.analysis.grants.some((g) => g.operation === 'python.import'));
});

test('two venv entry points do not share startup identity through a base interpreter symlink', async () => {
  const targets = [];
  for (const name of ['one', 'two']) {
    const bin = root + '/' + name + '/bin';
    await mkdir(bin, { recursive: true });
    await symlink(await realpath(exe), bin + '/python');
    const result = await inspect(`${quote(bin + '/python')} -B -c 'pass'`);
    assert.equal(result.analysis.complete, false);
    targets.push(result.analysis.grants.find((g) => g.operation === 'python.startup')?.target);
  }
  assert.ok(targets.every(Boolean));
  assert.notEqual(targets[0], targets[1]);
});

test('Python stdin uses exact literal input and never guesses an inherited file position', async () => {
  const body = "open('input').read()\n";
  await writeFile(root + '/stdin.py', body);
  const shell = await inspect(`${quote(exe)} -I -S -B - < ${quote(root + '/stdin.py')}`);
  assert.equal(shell.analysis.complete, true, JSON.stringify(shell.analysis.unresolved));
  const child = await inspect(
    commandFor(
      `import subprocess\nf=open('stdin.py')\nf.read(1)\nsubprocess.run([${JSON.stringify(exe)},'-I','-S','-B','-'],stdin=f)`,
    ),
  );
  assert.equal(child.analysis.complete, false);
  assert.ok(child.analysis.unresolved.some((u) => u.reason === 'python_stdin_file_position'));
  const literal = await inspect(
    commandFor(
      `import subprocess\nsubprocess.run([${JSON.stringify(exe)},'-I','-S','-B','-'],input=${JSON.stringify(body)},text=True)`,
    ),
  );
  assert.equal(literal.analysis.complete, true, JSON.stringify(literal.analysis.unresolved));
});

test('changed runtime code and new import candidates prevent static approval', async () => {
  const changed = structuredClone(config);
  changed.staticPython.environments[0].files[0].sha256 = '0'.repeat(64);
  const result = await inspect(commandFor("open('input').read()"), [], { config: changed });
  assert.equal(result.analysis.complete, false);
  assert.ok(result.analysis.unresolved.some((u) => u.reason === 'python_parser_changed'));
  const directory = root + '/import-fixture';
  await mkdir(directory);
  const shadow = structuredClone(config);
  shadow.staticPython.environments[0].directories.push({
    path: directory,
    realpath: directory,
    entries: [],
  });
  await writeFile(directory + '/ast.py', "raise RuntimeError('must not run')\n");
  const blocked = await inspect(commandFor("open('input').read()"), [], { config: shadow });
  assert.equal(blocked.analysis.complete, false);
  assert.ok(blocked.analysis.unresolved.some((u) => u.reason === 'python_environment_changed'));
});
