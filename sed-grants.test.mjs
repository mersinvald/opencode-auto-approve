import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, symlink } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { sedInvocation, sedProgram } from './sed-inspection.mjs';
import { gate } from './grant-gate.mjs';
import { sha256 } from './shell-host.mjs';

const base = await mkdtemp(realpathSync(tmpdir()) + '/approval-sed-');
const repo = base + '/repo',
  scratch = base + '/scratch';
await mkdir(repo);
await mkdir(scratch);
await writeFile(repo + '/input', 'alpha\nbeta\ngamma\n');
await writeFile(repo + '/other', 'delta\n');
await writeFile(repo + '/.env', 'fixture-secret\n');
await writeFile(repo + '/AGENTS.md', 'fixture instructions\n');
await writeFile(repo + '/policy', '{}\n');
const parser = fileURLToPath(new URL('./bin/shell-parser', import.meta.url));
const config = {
  skillRoots: [],
  protectedRoots: [repo + '/policy'],
  staticShell: {
    enabled: true,
    parser: { path: parser, sha256: sha256(await readFile(parser)) },
  },
};
const scope = { directory: repo, scratch, agent: 'orchestrator' };
const rule = (operation, target = repo, mode = 'allow', targetType = 'directory') => ({
  operation,
  target,
  mode,
  targetType,
  scope: 'project',
  authority: 'user',
});
async function inspect(command, { rules = [], readOnly = false } = {}) {
  return gate(
    {
      action: 'shell',
      effect: 'ask',
      directory: repo,
      resources: [command],
      tool: { name: 'shell', input: { command, workdir: repo } },
    },
    {
      scope: { ...scope, readOnly },
      config,
      runtime: { command, cwd: repo, shell: '/bin/bash', env: { PATH: '/usr/bin:/bin' } },
      permissions: { sessions: [], agent: { rules: [] } },
      state: { rules },
    },
  );
}
const inplace = process.platform === 'darwin' ? "-i ''" : '-i';
const sh = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
const effects = (result) => result.analysis.grants.map((g) => [g.operation, g.target]);

test('sed print ranges, filters, multiple expressions and pipelines are complete read effects', async () => {
  for (const command of [
    "sed -n '1, 20 p' input",
    "sed -n '/^alpha/,/gamma/p' input",
    "sed -nE -e '/alpha|beta/p' -e '3q' input other",
    "sed -e 's|alpha|beta|g' -e '/gamma/d' input",
    "sed 's/alpha/beta/; s/gamma/delta/' input",
    "sed -n '1,3{p;}' input",
    "sed -e 'y/abc/ABC/' -e 'h;g;p;=' input",
    "sed -n '1p;2p' < input",
    "cat input | sed -n '1,3p' | sed 's/^/  /'",
    "sed '/alpha/d' input > '" + scratch + "/output'",
    "sed -- 's/a/b/' input",
  ]) {
    const result = await inspect(command);
    assert.equal(result.analysis.complete, true, `${command}: ${result.analysis.reason}`);
    assert.equal(result.decision, 'allow', command);
    assert.ok(effects(result).some(([op, p]) => op === 'files.read' && p === repo + '/input'));
  }
});

test('in-place edits and backup writes use existing atomic rules, including Always ask precedence', async () => {
  const command = `sed ${inplace} -e 's/alpha/beta/' input`;
  const initial = await inspect(command);
  assert.equal(initial.analysis.complete, true, initial.analysis.reason);
  assert.equal(initial.decision, 'dynamic');
  assert.deepEqual(
    effects(initial).sort(),
    [
      ['files.read', repo + '/input'],
      ['files.write', repo + '/input'],
    ].sort(),
  );
  assert.equal((await inspect(command, { rules: [rule('files.write')] })).decision, 'allow');
  if (process.platform === 'darwin')
    assert.equal(
      (await inspect(command.replace("-i ''", '-i ""'), { rules: [rule('files.write')] })).decision,
      'allow',
    );
  assert.equal(
    (
      await inspect(command, {
        rules: [rule('files.write'), rule('files.write', repo + '/input', 'ask', 'file')],
      })
    ).decision,
    'ask',
  );
  const backupCommand = "sed -i.bak 's/alpha/beta/' input other";
  const backedUp = await inspect(backupCommand, { rules: [rule('files.write')] });
  assert.equal(backedUp.decision, 'allow', JSON.stringify(backedUp.analysis));
  for (const p of ['input', 'other', 'input.bak', 'other.bak'])
    assert.ok(
      effects(backedUp).some(([op, target]) => op === 'files.write' && target === repo + '/' + p),
    );
  assert.equal(
    (
      await inspect(backupCommand, {
        rules: [rule('files.write', repo + '/input', 'allow', 'file')],
      })
    ).decision,
    'dynamic',
  );
  const readOnly = await inspect(command, { rules: [rule('files.write')], readOnly: true });
  assert.notEqual(readOnly.decision, 'allow');
  assert.equal(
    await readFile(repo + '/input', 'utf8'),
    'alpha\nbeta\ngamma\n',
    'Analysis must not execute sed',
  );
});

test('embedded reads and writes are real grants, even under addresses or substitution flags', async () => {
  for (const program of [
    'w output',
    '1w output',
    's/a/b/w output',
    'p;w output',
    '1{w output\n}',
    'W output',
  ]) {
    const result = await inspect(`sed ${sh(program)} input`);
    assert.equal(result.analysis.complete, true, `${program}: ${result.analysis.reason}`);
    assert.equal(result.decision, 'dynamic');
    assert.ok(effects(result).some(([op, p]) => op === 'files.write' && p === repo + '/output'));
  }
  const result = await inspect("sed -e 'r other' -e 's/a/b/w " + scratch + "/output' input");
  assert.equal(result.decision, 'allow');
  assert.ok(effects(result).some(([op, p]) => op === 'files.read' && p === repo + '/other'));
  assert.ok(effects(result).some(([op, p]) => op === 'files.write' && p === scratch + '/output'));
  for (const [command, expected] of [
    ["sed 'r .env' input", 'secrets.read'],
    [`sed ${inplace} 's/a/b/' .env`, 'secrets.write'],
    [`sed ${inplace} 's/a/b/' policy`, 'policy.write'],
    ["sed -n '1p' AGENTS.md", 'instructions.read'],
  ]) {
    const result = await inspect(command, { rules: [rule('files.*')] });
    assert.ok(
      effects(result).some(([op]) => op === expected),
      command,
    );
    if (expected !== 'instructions.read') assert.notEqual(result.decision, 'allow');
  }
});

test('BSD and GNU options retain the exact program, input files and backup suffix', () => {
  for (const [dialect, args, suffix] of [
    ['bsd', ['-i', '', 's/a/b/', 'input'], ''],
    ['bsd', ['-i', '.old', '-e', 's/a/b/', 'input'], '.old'],
    ['gnu', ['-i', '-e', 's/a/b/', 'input'], ''],
    ['gnu', ['-ni', 's/a/b/p', 'input'], ''],
    ['gnu', ['--in-place=.bak', '--expression=s/a/b/', 'input'], '.bak'],
    ['gnu', ['-i.bak', 's/a/b/', 'input'], '.bak'],
    ['bsd', ['-i.bak', 's/a/b/', 'input'], '.bak'],
  ]) {
    const p = sedInvocation(args, { dialect });
    assert.equal(p.inPlace, true);
    assert.equal(p.suffix, suffix);
    assert.deepEqual(p.inputs, ['input']);
  }
  for (const args of [
    ['-i', 's/a/b/', 'input'],
    ['--in-place', 's/a/b/', 'input'],
  ])
    assert.throws(() => sedInvocation(args), /sed_dialect/);
  const multi = sedInvocation(['-ne1p', '-e', '2p', '--', '-file'], { dialect: 'gnu' });
  assert.deepEqual(multi.inputs, ['-file']);
});

test('unknown syntax and command execution never become complete file-only permissions', async () => {
  for (const program of [
    'e touch output',
    's/a/b/e',
    's/a/b/ge',
    '/a/{e touch output\n}',
    's|a|b|; e touch output',
    'p\ne touch output',
    's/a/b/\x65',
    's/a/b/;w output;e touch other',
    's/a/b/w output; e touch other',
    's/[a/;e touch output/',
    's/a/b/\\\ne touch output',
    'p UNKNOWN',
    'v',
    'a\\\ntext\\\ne touch output',
  ]) {
    assert.throws(() => sedProgram(program), undefined, program);
    const result = await inspect(`sed ${sh(program)} input`, { rules: [rule('files.*')] });
    assert.equal(result.analysis.complete, false, program);
    assert.notEqual(result.decision, 'allow', program);
  }
  for (const command of [
    'sed -f helper.sed input',
    "sed --follow-symlinks -i.bak 's/a/b/' input",
    "sed -i'../*' 's/a/b/' input",
    "sed 'p' -i.bak input",
  ])
    assert.equal(
      (await inspect(command, { rules: [rule('files.*')] })).analysis.complete,
      false,
      command,
    );
  await symlink(repo + '/input', repo + '/link');
  assert.equal(
    (await inspect(`sed ${inplace} 's/a/b/' link`, { rules: [rule('files.*')] })).analysis.complete,
    false,
  );
  await symlink(repo + '/other', repo + '/input.bak');
  assert.equal(
    (await inspect("sed -i.bak 's/a/b/' input", { rules: [rule('files.*')] })).analysis.complete,
    false,
  );
});
