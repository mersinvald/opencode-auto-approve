import test from 'node:test';
const sandboxWrapper =
  process.platform === 'darwin'
    ? "/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' "
    : '';

import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, lstat, chmod, symlink, open } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gate } from './grant-gate.mjs';
import { sha256, attestRuntime } from './shell-host.mjs';
import { reviewPrompt } from './grant-decision.mjs';

const base = await mkdtemp(
    (await import('node:fs')).realpathSync((await import('node:os')).tmpdir()) +
      '/approval-audit-targets-',
  ),
  repo = base + '/repo',
  scratch = base + '/scratch';
await mkdir(repo);
await mkdir(scratch, { mode: 0o700 });
await mkdir(repo + '/contracts');
await writeFile(repo + '/contracts/common.json', '{"$ref":"common.json"}\n');
await writeFile(repo + '/contracts/copy.json', '{"$ref":"common.json"}\n');
execFileSync('/usr/bin/git', ['init', '-q', repo]);
const executables = [];
for (const name of ['bd', 'jq']) {
  const file = base + '/' + name;
  // Any accidental execution leaves evidence; these programs are only parsed.
  await writeFile(file, `#!/bin/sh\nprintf executed > '${base}/EXECUTED'\n`, { mode: 0o700 });
  executables.push({ name, path: file, realpath: file, sha256: sha256(await readFile(file)) });
}
await mkdir(repo + '/.beads/embeddeddolt', { recursive: true });
await writeFile(
  repo + '/.beads/metadata.json',
  JSON.stringify({
    backend: 'dolt',
    dolt_mode: 'embedded',
    database: 'dolt',
    dolt_database: 'fixture',
  }),
);
await writeFile(repo + '/.beads/config.yaml', 'dolt.local-only: true\n');
const parser = fileURLToPath(new URL('./bin/shell-parser', import.meta.url));
const config = {
  skillRoots: [],
  protectedRoots: [base + '/policy'],
  staticShell: {
    enabled: true,
    parser: { path: parser, sha256: sha256(await readFile(parser)) },
    executables,
    beadsWriters: ['orchestrator'],
  },
};
const scope = { directory: repo, scratch, agent: 'orchestrator' };
const rule = (operation, target, mode = 'allow') => ({
  operation,
  target,
  targetType: 'directory',
  mode,
  scope: 'project',
  authority: 'user',
});
async function inspect(command, options = {}) {
  const request = {
    action: 'shell',
    effect: 'ask',
    resources: [command],
    directory: repo,
    tool: { name: 'shell', input: { command, workdir: repo } },
  };
  return gate(request, {
    scope,
    config,
    runtime: { command, cwd: repo, shell: '/bin/bash', env: { PATH: base + ':/usr/bin:/bin' } },
    permissions: { sessions: [], agent: { rules: [] } },
    state: { rules: [] },
    ...options,
  });
}
async function allowed(command, options) {
  const result = await inspect(command, options);
  assert.equal(result.decision, 'allow', JSON.stringify(result.analysis));
  return result;
}
async function incomplete(command) {
  const result = await inspect(command);
  assert.equal(result.analysis.complete, false, command);
  assert.notEqual(result.decision, 'allow', command);
  return result;
}

test('exact null redirects preserve existing read grants without arbitrary device permissions', async () => {
  const a = await allowed(
    'git status --porcelain=v1 --untracked-files=all; find contracts -type f 2>/dev/null | wc -l; cat </dev/null >/dev/null',
  );
  assert.ok(a.analysis.snapshots.some((s) => s.resolved === '/dev/null' && s.rdev !== undefined));
  assert.ok(!a.analysis.grants.some((g) => g.target === '/dev/null'));
  await symlink('/dev/null', scratch + '/null-alias');
  for (const dest of ['/dev/zero', scratch + '/null-alias', '/dev/../dev/null'])
    await incomplete(`printf text > '${dest}'`);
  await incomplete('cat 1</dev/null');
});

test('observed Git forms and global option ordering reuse git.read', async () => {
  for (const command of [
    'git show --stat HEAD',
    'git --no-pager show --stat HEAD | head -50',
    'git branch -avv',
    'git ls-tree --name-only HEAD contracts',
    'git status --short contracts',
    `git -C '${repo}' --no-pager -C . status --short -- contracts`,
    `git --no-pager -C '${repo}' ls-tree --name-only 0123456789abcdef0123456789abcdef01234567 contracts`,
  ]) {
    const a = await allowed(command);
    assert.ok(a.analysis.grants.some((g) => g.operation === 'git.read' && g.target === repo));
  }
  for (const args of [
    'branch -D main',
    'branch --edit-description',
    'show --output=/tmp/escape HEAD',
    'show --ext-diff --stat HEAD',
    '-c core.fsmonitor=evil status',
    '--git-dir=/tmp/elsewhere status',
    'ls-tree --name-only HEAD ../outside',
    "status --short ':(top)contracts'",
    'status --short -- ../outside',
    'branch --list --format=%(contents:signature)',
    'config --global user.name attacker',
  ])
    await incomplete('git ' + args);
});

test('show still rejects external diff and Git still rejects fsmonitor execution', async () => {
  for (const setting of [
    'diff.external',
    'diff.foo.textconv',
    'core.fsmonitor',
    'log.showSignature',
  ]) {
    execFileSync('/usr/bin/git', [
      '-C',
      repo,
      'config',
      setting,
      setting === 'log.showSignature' ? 'true' : 'unsafe',
    ]);
    try {
      await incomplete('git show --stat HEAD');
    } finally {
      execFileSync('/usr/bin/git', ['-C', repo, 'config', '--unset', setting]);
    }
  }
});

test('inspection filters normalize data programs and flag arguments', async () => {
  for (const command of [
    String.raw`grep -o '"\$ref": "[^"]*"' contracts/*.json | sed 's/.*"\$ref": "//' | sort | uniq -c | sort -rn`,
    String.raw`git status --porcelain -- contracts | sed 's/^/  /'`,
    `find . -path ./.git -prune -o -type f -print | sort`,
    'test ! -d contracts/venv',
    'grep -rn ref contracts/*.json | sort -u -t: -k1,1 | head -40',
    'grep -n ref contracts/*.json | sort -t : -k 1,1',
    'echo ---; echo "---HEAD---"',
    'cmp contracts/common.json contracts/copy.json',
  ])
    await allowed(command);
  for (const command of [
    "sed -i '' 's/a/b/' contracts/common.json",
    "sed 's/a/b/e' contracts/common.json",
    "sed 's/a/b/w /tmp/escape' contracts/common.json",
    "sed 's/a/b/;w /tmp/escape' contracts/common.json",
    "sed 'r /etc/passwd' contracts/common.json",
    'sort -o /tmp/escape contracts/common.json',
    'uniq contracts/common.json /tmp/escape',
    'find . -prune -o -exec evil {} +',
    'find . -delete',
    'grep -r ref .',
  ])
    await incomplete(command);
});

function beadsCommand(payload = '{"next":"continue"}') {
  return `set -e
S='${scratch}'; P='${repo}'
BD=(${sandboxWrapper}'${base}/bd' --sandbox --dolt-auto-commit off --actor fixture -C "$P")
cat > "$S/data.json" <<'EOF'
${payload}
EOF
jq --argjson d "$(cat "$S/data.json")" '.[0].metadata + {phase1_loop_attempt:$d,current_status:"in_progress",current_verdict:null,next_action:$d.next}' < <("\${BD[@]}" --readonly show fixture --json) > "$S/merged.json"
"\${BD[@]}" update fixture --status in_progress --metadata "$(cat "$S/merged.json")"
printf 'Beads updated\\n'`;
}
const beadsRules = [rule('beads.read', repo), rule('beads.update', repo)];
test('observed Beads metadata substitutions reuse repository grants across payloads without execution', async () => {
  let ids;
  for (const payload of ['{"next":"continue"}', '{"next":"review","pins":{"head":"abc"}}']) {
    const a = await allowed(beadsCommand(payload), { state: { rules: beadsRules } });
    const next = a.analysis.grants.map((g) => g.id).sort();
    if (ids) assert.deepEqual(next, ids);
    ids = next;
    assert.ok(a.analysis.commands.some((c) => c.argv.some((a) => a?.symbolic === 'json-object')));
    assert.ok(!a.analysis.grants.some((g) => g.operation === 'shell.opaque'));
  }
  await allowed(
    beadsCommand().replace(
      '.[0].metadata + {phase1_loop_attempt:$d,current_status:"in_progress",current_verdict:null,next_action:$d.next}',
      '.[0].metadata + $d | .unresolved_findings=[] | .pending_child="fixture"',
    ),
    { state: { rules: beadsRules } },
  );
  for (const file of ['EXECUTED', 'scratch/data.json', 'scratch/merged.json'])
    assert.equal(await lstat(base + '/' + file).catch(() => null), null);
});

test('metadata review respects writer roles, ask rules, and operation granularity', async () => {
  const command = beadsCommand();
  assert.equal(
    (
      await inspect(command, {
        scope: { ...scope, agent: 'oracle', readOnly: true },
        state: { rules: beadsRules },
      })
    ).decision,
    'ask',
  );
  assert.equal(
    (await inspect(command, { state: { rules: [rule('files.write', repo)] } })).decision,
    'dynamic',
  );
  assert.equal(
    (
      await inspect(command, {
        state: { rules: [rule('beads.read', repo), rule('beads.update', repo, 'ask')] },
      })
    ).decision,
    'ask',
  );
  const close = command.replace(
    'update fixture --status in_progress',
    'update fixture --status closed',
  );
  const a = await inspect(close, { state: { rules: beadsRules } });
  assert.equal(a.decision, 'dynamic');
  assert.ok(a.analysis.grants.some((g) => g.operation === 'beads.manage'));
});

test('unknown substitutions, JSON file loaders, and mutating producers fail closed', async () => {
  for (const command of [
    beadsCommand().replace('$(cat "$S/data.json")', '$(touch /tmp/escape; cat "$S/data.json")'),
    beadsCommand().replace(
      '$(cat "$S/data.json")',
      '$(printf unsafe > "$S/data.json"; cat "$S/data.json")',
    ),
    beadsCommand().replace(' < <(', ' < >('),
    beadsCommand().replace('--argjson d', '--rawfile d'),
    beadsCommand().replace('--argjson d', '--argjson ENV').replaceAll('$d', '$ENV'),
    beadsCommand().replace("'.[0].metadata +", "'input_filename | .[0].metadata +"),
    beadsCommand().replace("'.[0].metadata +", '\'import "evil"; .[0].metadata +'),
    beadsCommand().replace('"$(cat "$S/merged.json")"', '$(cat "$S/merged.json")'),
    beadsCommand().replace('"$(cat "$S/merged.json")"', '"prefix$(cat "$S/merged.json")"'),
    beadsCommand()
      .replace('"$(cat "$S/merged.json")"', '"$(cat "$S/data.json")"')
      .replace('{"next":"continue"}', '"@/etc/passwd"'),
    'cat "$(cat contracts/common.json)"',
    beadsCommand().replace('$(cat "$S/merged.json")', '$(echo @/etc/passwd; cat "$S/merged.json")'),
    beadsCommand().replace(
      '$(cat "$S/merged.json")',
      '$({ echo @/etc/passwd; cat "$S/merged.json"; })',
    ),
    beadsCommand().replace('jq --argjson', 'printf invalid > "$S/data.json"; jq --argjson'),
    beadsCommand().replace('jq --argjson', 'rm -rf "$S"; jq --argjson'),
  ])
    await incomplete(command);
});

test('scratch cleanup is a separate bounded delete effect', async () => {
  const directory = scratch + '/review';
  await mkdir(directory);
  await writeFile(directory + '/result.txt', 'keep');
  const a = await allowed(`S='${scratch}'; rm -rf "$S/review"; mkdir -p "$S/review"`);
  assert.ok(
    a.analysis.grants.some((g) => g.operation === 'files.delete' && g.target === directory),
  );
  assert.equal(await readFile(directory + '/result.txt', 'utf8'), 'keep');
  assert.equal(
    (await inspect(`rm -rf '${directory}'`, { scope: { ...scope, readOnly: true } })).decision,
    'ask',
  );
  assert.equal(
    (
      await inspect(`rm -rf '${directory}'`, {
        state: { rules: [rule('files.delete', directory, 'ask')] },
      })
    ).decision,
    'ask',
  );
  for (const target of [scratch, scratch + '/..', repo, base + '/other'])
    await incomplete(`rm -rf '${target}'`);
  await symlink(repo, directory + '/escape');
  await incomplete(`rm -rf '${directory}'`);
  await chmod(scratch, 0o777);
  try {
    await incomplete(`rm -rf '${scratch}/empty'`);
  } finally {
    await chmod(scratch, 0o700);
  }
});

test('scratch cleanup cannot delete policy or secret files under ordinary delete rules', async () => {
  for (const file of ['AGENTS.md', '.env']) {
    const directory = scratch + '/' + file.replaceAll('.', '_');
    await mkdir(directory);
    await writeFile(directory + '/' + file, 'fixture');
    const a = await inspect(`rm -rf '${directory}'`);
    assert.notEqual(a.decision, 'allow');
    assert.ok(
      a.analysis.grants.some(
        (g) => g.operation === (file === 'AGENTS.md' ? 'policy.delete' : 'secrets.delete'),
      ),
    );
  }
});

test('prompt prefers bounded recurring inspection grants while honoring one-time restrictions', () => {
  const prompt = reviewPrompt({ candidates: [{ id: 'g_0123456789abcdef01234567' }] });
  assert.match(
    prompt,
    /prefer allow_always for repeated local inspection \(git.read, files.read, files.list, files.access\)/,
  );
  assert.match(prompt, /once only or do not remember/);
  assert.match(prompt, /git.read scoped to its repository/);
});

// Embedded Dolt makes the installed, explicitly pinned Beads binary 128 MiB.
test('explicit binary pins support Beads size but still reject hash and permission drift', async () => {
  const file = base + '/large-bd',
    handle = await open(file, 'w', 0o700);
  await handle.truncate(65 * 1024 * 1024);
  await handle.close();
  const pin = {
    name: 'large-bd',
    path: file,
    realpath: file,
    sha256: sha256(await readFile(file)),
  };
  const runtime = { shell: '/bin/bash', env: { PATH: base + ':/usr/bin:/bin' } };
  const settings = { executables: [pin] };
  assert.equal(await (await attestRuntime(runtime, settings)).resolveExecutable(file), file);
  const fd = await open(file, 'r+');
  await fd.write(Buffer.from('changed'), 0, 7, 0);
  await fd.close();
  assert.equal(await (await attestRuntime(runtime, settings)).resolveExecutable(file), null);
  await chmod(file, 0o722);
  assert.equal(await (await attestRuntime(runtime, settings)).resolveExecutable(file), null);
});
