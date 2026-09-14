import path from 'node:path';
import { lstat, readFile, realpath, readdir } from 'node:fs/promises';
import { grant } from './grant-rules.mjs';
import { canonical, digest, secretPath, policyPath, requestDirectory, within } from './policy.mjs';
import { parseShell, attestRuntime, executableResolver } from './shell-host.mjs';
import { pythonInvocation } from './python-invocation.mjs';
import { parsePythonSource, readPythonHelper, attestPythonEnvironment } from './python-host.mjs';
import { pythonEffects } from './python-effects.mjs';
import { repositoryScope } from './repository-scope.mjs';
import { literal, expandWord, arrayExpansion } from './shell-words.mjs';
import { sedInvocation } from './sed-inspection.mjs';
import { sqliteRead } from './sqlite-read.mjs';
import { safeMetadataFilter, gitInspection } from './shell-inspection.mjs';

const fail = (reason, diagnostic) => {
  throw Object.assign(Error(reason), { diagnostic });
};
const jsonKind = (value) => {
  try {
    const x = JSON.parse(value);
    return x && typeof x === 'object' && !Array.isArray(x) ? 'json-object' : 'json';
  } catch {
    return undefined;
  }
};
const symbolic = (value) =>
  value && typeof value === 'object' && ['json', 'json-object'].includes(value.symbolic);
const nameRE = /^(?:[A-Za-z_][A-Za-z0-9_]*)$/;
const special =
  /^(?:PATH|HOME|ENV|BASH_ENV|ZDOTDIR|IFS|CDPATH|SHELL|GIT_.*|BD_.*|BEADS_.*|DOLT_.*|PYTHON.*)$/;
function fileOperation(effect, target, lexical, config) {
  if (
    ['write', 'delete'].includes(effect) &&
    policyPath(target, [...config.protectedRoots, ...config.skillRoots])
  )
    return 'policy.' + effect;
  if (secretPath(target) || secretPath(lexical))
    return ['write', 'delete'].includes(effect) ? 'secrets.' + effect : 'secrets.read';
  if (
    effect === 'read' &&
    path.basename(target) === 'AGENTS.md' &&
    path.basename(lexical) === 'AGENTS.md'
  )
    return 'instructions.read';
  return 'files.' + effect;
}

// Adapters describe effects only. They never consult permission rules.
export async function extractAction(request, { scope, config, runtime, permissions, signal }) {
  const items = new Map(),
    commands = [],
    snapshots = [],
    globRoots = new Set();
  const pythonUnresolved = [],
    shellUnresolved = [];
  let sourceLocation,
    pythonDepth = 0;
  const constraints = {
    readOnly: !!scope.readOnly,
    beadsWriter: (config.staticShell?.beadsWriters ?? ['orchestrator']).includes(scope.agent),
    deny: [
      ...new Set(
        [
          ...(permissions?.sessions ?? []).flatMap((s) => s.rules ?? []),
          ...(permissions?.agent?.rules ?? []),
        ]
          .filter((r) => r.effect === 'deny')
          .map((r) => JSON.stringify(r)),
      ),
    ].sort(),
  };
  const add = (op, target, type = 'file', extra) => {
    const item = grant(op, target, type, extra);
    const locations = [
      ...(items.get(item.id)?.locations ?? []),
      ...(sourceLocation ? [sourceLocation] : []),
    ];
    if (locations.length)
      item.locations = [...new Map(locations.map((p) => [JSON.stringify(p), p])).values()].slice(
        0,
        64,
      );
    items.set(item.id, item);
    return item;
  };
  const changed = new Map();
  let mutation = 0;
  const target = async (raw, cwd, effect = 'read', targetType) => {
    const lexical = path.resolve(cwd, raw),
      resolved = await canonical(raw, cwd);
    let stat;
    try {
      stat = await lstat(resolved);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    if (stat && !stat.isFile() && !stat.isDirectory()) fail('special_file');
    if (effect === 'write' && stat?.isFile() && stat.nlink > 1) fail('hardlinked_write');
    if (['write', 'delete'].includes(effect)) changed.set(resolved, ++mutation);
    const op = fileOperation(
      effect === 'read' && stat?.isDirectory() ? 'list' : effect,
      resolved,
      lexical,
      config,
    );
    add(
      op,
      resolved,
      targetType ??
        (stat?.isDirectory() || effect === 'access' || effect === 'list' ? 'directory' : 'file'),
    );
    snapshots.push({ lexical, resolved, dev: stat?.dev, ino: stat?.ino, mode: stat?.mode });
    return resolved;
  };
  let complete = true,
    reason,
    failureDiagnostic,
    host,
    syntax;
  const authority = new Set(config.staticShell?.zshStartup?.files?.map((f) => f.path) ?? []);
  const gitRoots = new Set();
  let gitInputsUnresolved = false;
  try {
    if (['read', 'edit', 'external_directory', 'glob', 'grep'].includes(request.action)) {
      if (request.action === 'grep') {
        const input = request.tool?.name === 'grep' && request.tool.input;
        if (
          !input ||
          typeof input.pattern !== 'string' ||
          !request.resources?.length ||
          !request.resources.every((r) => r === input.pattern)
        )
          fail('grep_resource_mismatch');
        const file = await target(input.path ?? '.', request.directory, 'read');
        // Resolve concrete candidates conservatively, including hidden files
        // and symlink targets. A parent read rule cannot hide a secret child.
        const visited = new Set();
        let count = 0;
        const scan = async (directory) => {
          if (visited.has(directory)) fail('grep_cycle');
          visited.add(directory);
          if (visited.size > 64) fail('grep_scope_limit');
          const entries = await readdir(directory, { withFileTypes: true });
          if (entries.length + count > 128) fail('grep_scope_limit');
          count += entries.length;
          for (const entry of entries) {
            const child = await target(path.join(directory, entry.name), directory, 'read');
            if ((await lstat(child)).isDirectory()) await scan(child);
          }
        };
        if ((await lstat(file)).isDirectory()) await scan(file);
        return { complete: true, grants: [...items.values()], commands, snapshots };
      }
      if (
        request.action === 'glob' &&
        request.tool?.name === 'glob' &&
        typeof request.tool.input?.pattern === 'string'
      ) {
        const input = request.tool.input;
        if (!request.resources?.every((r) => r === input.pattern)) fail('glob_resource_mismatch');
        if (path.isAbsolute(input.pattern) || input.pattern.split('/').includes('..'))
          fail('glob_scope');
        await target(input.path ?? '.', request.directory, 'list');
        return { complete: true, grants: [...items.values()], commands, snapshots };
      }
      if (request.action === 'external_directory' && request.tool?.name === 'read') {
        const name = request.tool.input?.filePath ?? request.tool.input?.path;
        if (typeof name === 'string') {
          const resolved = await canonical(name, request.directory);
          const lexical = path.resolve(request.directory, name),
            stat = await lstat(resolved);
          const parents = [
            path.dirname(resolved),
            path.dirname(lexical),
            ...(stat.isDirectory() ? [resolved, lexical] : []),
          ];
          const resources = await Promise.all(
            request.resources.map((r) => canonical(r, request.directory)),
          );
          if (resources.length && resources.every((r) => parents.includes(r))) {
            await target(name, request.directory, 'read');
            return { complete: true, grants: [...items.values()], commands, snapshots };
          }
          fail('read_directory_mismatch');
        }
      }
      const effect = {
        read: 'read',
        edit: 'write',
        external_directory: 'access',
        glob: 'list',
        grep: 'read',
      }[request.action];
      for (const raw of request.resources)
        await target(raw.replace(/\/\*$/, ''), request.directory, effect);
    } else if (request.action === 'shell' && request.tool?.name === 'shell') {
      const command = request.tool.input.command,
        cwd = requestDirectory(request);
      const ast = await parseShell(
        command,
        config.staticShell,
        path.basename(runtime?.shell ?? '/bin/zsh'),
        signal,
      );
      syntax =
        JSON.stringify(ast).length < 96000 ? ast : { omitted: 'AST exceeds audit size budget' };
      if (runtime?.command === command && runtime.cwd === cwd)
        host = await attestRuntime(runtime, config.staticShell);
      else fail('runtime_unavailable');
      let visits = 0;
      const pathArgs = async (args, state, effect = 'read') => {
        for (const arg of args) await target(arg, state.cwd, effect);
      };
      const exec = async (argv, state, piped) => {
        if (typeof argv[0] !== 'string') fail('dynamic_executable');
        const name = path.basename(argv[0]),
          args = argv.slice(1);
        if (args.some((x) => typeof x !== 'string') && !['jq', 'bd', 'sandbox-exec'].includes(name))
          fail('dynamic_argument');
        commands.push({
          argv,
          cwd: state.cwd,
          ...(state.cdBranch ? { cdBranch: state.cdBranch } : {}),
          ...(state.environment ? { environment: state.environment } : {}),
        });
        const commandHost = state.commandHost ?? host;
        const executable = await commandHost.resolveExecutable(argv[0], !state.directProcess);
        if (!executable) fail('unverified_executable');
        if (!executable.startsWith('builtin:')) authority.add(executable);
        if (['true', 'false', 'pwd'].includes(name) && !args.length) return;
        if (name === 'set') {
          if (
            args.length &&
            args.every(
              (v, i) =>
                /^-[eu]+$/.test(v) ||
                (v === '-o' && args[i + 1] === 'pipefail') ||
                (v === 'pipefail' && ['-o', '-euo', '-uo', '-eo'].includes(args[i - 1])) ||
                (['-euo', '-uo', '-eo'].includes(v) && args[i + 1] === 'pipefail'),
            )
          )
            return;
          fail('shell_options');
        }
        if (name === 'echo') return;
        if (
          name === 'printf' &&
          args.length &&
          !args[0].startsWith('-') &&
          (!/%/.test(args[0]) || ['%s', '%s\\n', '%s\n'].includes(args[0]))
        )
          return;
        if (['test', '['].includes(name)) {
          const a = name === '[' && args.at(-1) === ']' ? args.slice(0, -1) : [...args];
          if (a[0] === '!') a.shift();
          if (a.length !== 2 || !['-e', '-f', '-d'].includes(a[0])) fail('test_expression');
          await target(a[1], state.cwd, 'list');
          return;
        }
        if (name === 'sed') {
          const dialect =
            process.platform === 'darwin' && executable === '/usr/bin/sed'
              ? 'bsd'
              : process.platform === 'linux' || /-gnused-[^/]+\/bin\/sed$/.test(executable)
                ? 'gnu'
                : 'unknown';
          const parsed = sedInvocation(args, { dialect, piped });
          await pathArgs([...parsed.inputs, ...parsed.reads], state);
          await pathArgs(parsed.writes, state, 'write');
          if (parsed.inPlace) {
            for (const file of parsed.inputs) {
              // In-place sed replaces the directory entry. Resolving a final
              // symlink as a normal write would authorize the wrong object.
              const lexical = path.resolve(state.cwd, file);
              if (!(await lstat(lexical)).isFile()) fail('sed_in_place_file');
              await target(file, state.cwd, 'write');
              if (parsed.suffix) {
                const backup = lexical + parsed.suffix;
                const st = await lstat(backup).catch((e) => {
                  if (e.code !== 'ENOENT') throw e;
                });
                if (st && !st.isFile()) fail('sed_backup_file');
                await target(backup, state.cwd, 'write');
              }
            }
          }
          return;
        }
        if (name === 'jq') {
          const a = [...args],
            variables = new Map();
          let raw = false;
          while (typeof a[0] === 'string' && a[0].startsWith('-')) {
            const flag = a.shift();
            if (/^-[rceS]+$/.test(flag)) {
              raw ||= flag.includes('r');
              continue;
            }
            if (flag !== '--argjson') fail('jq_program');
            const name = a.shift(),
              value = a.shift();
            if (
              !nameRE.test(name ?? '') ||
              ['ENV', 'ARGS', '__loc__'].includes(name) ||
              variables.has(name) ||
              variables.size >= 16 ||
              !(symbolic(value) || (typeof value === 'string' && jsonKind(value)))
            )
              fail('jq_argument');
            variables.set(name, symbolic(value) ? value.symbolic : jsonKind(value));
          }
          const filter = a.shift(),
            parsed =
              filter === '.'
                ? { kind: 'json' }
                : variables.size && safeMetadataFilter(filter, variables);
          if (
            !parsed ||
            a.some((x) => typeof x !== 'string' || x.startsWith('-')) ||
            (!a.length && !piped)
          )
            fail('jq_program');
          await pathArgs(a, state);
          return raw ? undefined : parsed.kind;
        }
        if (
          [
            'cat',
            'head',
            'tail',
            'wc',
            'grep',
            'ls',
            'sort',
            'shasum',
            'sha256sum',
            'cmp',
            'uniq',
          ].includes(name)
        ) {
          let files = [],
            pattern = name !== 'grep',
            ended = false;
          for (let i = 0; i < args.length; i++) {
            const a = args[i];
            if (!ended && a === '--') {
              ended = true;
              continue;
            }
            if (!ended && a.startsWith('-') && a !== '-') {
              if (
                (name === 'grep' && /^-[EFivwnHhclLqosbr]+$/.test(a)) ||
                (name === 'cat' && /^-[benstv]+$/.test(a)) ||
                (name === 'wc' && /^-[clmw]+$/.test(a)) ||
                (name === 'ls' && /^-[aldh1nFpt]+$/.test(a)) ||
                (name === 'sort' && /^-[unrf]+$/.test(a)) ||
                (['head', 'tail'].includes(name) && /^-\d{1,6}$/.test(a))
              )
                continue;
              if (
                (name === 'uniq' && /^-[cdu]+$/.test(a)) ||
                (name === 'cmp' && ['-s', '-l'].includes(a))
              )
                continue;
              if (
                name === 'sort' &&
                (/^-t[^\r\n]$/.test(a) || /^-k[1-9][0-9]{0,3}(?:,[1-9][0-9]{0,3})?$/.test(a))
              )
                continue;
              if (name === 'sort' && a === '-t' && args[i + 1]?.length === 1) {
                i++;
                continue;
              }
              if (
                name === 'sort' &&
                a === '-k' &&
                /^[1-9][0-9]{0,3}(?:,[1-9][0-9]{0,3})?$/.test(args[i + 1] ?? '')
              ) {
                i++;
                continue;
              }
              if (name === 'shasum' && a === '-a' && args[++i] === '256') continue;
              if (name === 'grep' && /^-[ABC]\d{1,6}$/.test(a)) continue;
              if (name === 'grep' && /^-[ABC]$/.test(a) && /^\d{1,6}$/.test(args[++i] ?? ''))
                continue;
              if (
                ['head', 'tail'].includes(name) &&
                /^-[nc]$/.test(a) &&
                /^\d{1,6}$/.test(args[++i] ?? '')
              )
                continue;
              fail('unsupported_flags');
            }
            if (!pattern) {
              pattern = true;
              continue;
            }
            if (a === '-' && piped) continue;
            files.push(a);
          }
          if (name === 'ls' && !files.length) files.push('.');
          if (!pattern || (!files.length && !piped)) fail('unbound_input');
          if ((name === 'uniq' && files.length > 1) || (name === 'cmp' && files.length !== 2))
            fail('filter_output');
          if (
            name === 'grep' &&
            args.some((x) => /^-[EFivwnHhclLqosbr]*r[EFivwnHhclLqosbr]*$/.test(x))
          )
            for (const file of files)
              if (!(await lstat(await canonical(file, state.cwd))).isFile())
                fail('recursive_grep_scope');
          await pathArgs(files, state, name === 'ls' ? 'list' : 'read');
          if (name === 'cat' && files.length === 1 && args.length === 1) {
            const file = await canonical(files[0], state.cwd),
              known = state.jsonFiles[file];
            if (
              known &&
              known.generation >=
                Math.max(
                  0,
                  ...[...changed]
                    .filter(([p]) => within(file, p) || within(p, file))
                    .map(([, v]) => v),
                )
            )
              return known.kind;
            if (![...changed.keys()].some((p) => within(file, p) || within(p, file))) {
              const stat = await lstat(file).catch(() => null);
              if (stat?.isFile() && stat.size <= 32768) {
                const body = await readFile(file, 'utf8');
                snapshots.push({ jsonSource: file, sha256: digest(body) });
                authority.add(file);
                return jsonKind(body);
              }
            }
          }
          if (name === 'cat' && !args.length) return state.inputKind;
          return;
        }
        if (name === 'find') {
          const a = [...args],
            roots = [];
          while (a.length && !a[0].startsWith('-') && !['!', '(', ')'].includes(a[0]))
            roots.push(a.shift());
          if (!roots.length) fail('find_roots');
          for (let i = 0; i < a.length; i++) {
            if (
              [
                '-not',
                '!',
                '-and',
                '-or',
                '-a',
                '-o',
                '(',
                ')',
                '-print',
                '-print0',
                '-prune',
              ].includes(a[i])
            )
              continue;
            if (a[i] === '-type' && ['f', 'd', 'l'].includes(a[++i])) continue;
            if (['-name', '-path'].includes(a[i]) && typeof a[++i] === 'string') continue;
            if (['-maxdepth', '-mindepth'].includes(a[i]) && /^\d{1,4}$/.test(a[++i])) continue;
            fail('find_effect');
          }
          await pathArgs(roots, state, 'list');
          return;
        }
        if (name === 'mkdir') {
          const a = args[0] === '-p' ? args.slice(1) : args;
          if (!a.length || a.some((x) => x.startsWith('-'))) fail('mkdir_flags');
          await pathArgs(a, state, 'write');
          return;
        }
        if (name === 'rm') {
          const a = [...args];
          let recursive = false;
          while (a[0]?.startsWith('-')) {
            const flag = a.shift();
            if (flag === '--') break;
            if (!/^-[rf]+$/.test(flag)) fail('cleanup_flags');
            recursive ||= flag.includes('r');
          }
          if (!recursive || !a.length || a.length > 16 || !scope.scratch) fail('cleanup_scope');
          const root = await realpath(scope.scratch),
            owner = await lstat(scope.scratch);
          if (
            root !== scope.scratch ||
            !owner.isDirectory() ||
            owner.uid !== process.getuid() ||
            owner.mode & 0o022
          )
            fail('cleanup_owner');
          let count = 0;
          const scan = async (file) => {
            if (++count > 512) fail('cleanup_limit');
            const stat = await lstat(file).catch((e) => {
              if (e.code !== 'ENOENT') throw e;
            });
            if (
              stat &&
              (stat.isSymbolicLink() ||
                stat.dev !== owner.dev ||
                stat.uid !== owner.uid ||
                (!stat.isDirectory() && !stat.isFile()))
            )
              fail('cleanup_escape');
            await target(file, state.cwd, 'delete');
            if (stat?.isDirectory())
              for (const child of await readdir(file)) await scan(path.join(file, child));
          };
          for (const raw of a) {
            if (raw.startsWith('-')) fail('cleanup_flags');
            const file = path.resolve(state.cwd, raw);
            if (file === root || !within(file, root) || (await canonical(file, state.cwd)) !== file)
              fail('cleanup_scope');
            await scan(file);
          }
          return;
        }
        if (['cp', 'tee'].includes(name)) {
          const a = args[0] === '--' ? args.slice(1) : args;
          if (
            !a.length ||
            a.some((x) => x.startsWith('-')) ||
            (name === 'cp' && a.length < 2) ||
            (name === 'tee' && !piped)
          )
            fail('write_flags');
          if (name === 'cp') {
            const destination = await canonical(a.pop(), state.cwd);
            const stat = await lstat(destination).catch((e) => {
              if (e.code !== 'ENOENT') throw e;
            });
            if (a.length > 1 && !stat?.isDirectory()) fail('copy_destination');
            for (const source of a) {
              await target(source, state.cwd, 'read');
              await target(
                stat?.isDirectory() ? path.join(destination, path.basename(source)) : destination,
                state.cwd,
                'write',
              );
            }
            return;
          }
          await pathArgs(a, state, 'write');
          return;
        }
        if (name === 'git') {
          const a = [...args];
          let root = state.cwd;
          while (a[0]?.startsWith('-')) {
            const flag = a.shift();
            if (['--no-pager', '-P'].includes(flag)) continue;
            if (flag === '-C' && a.length) {
              root = await target(a.shift(), root, 'access');
              continue;
            }
            fail('git_flags');
          }
          const operation = a.shift(),
            repo = await repositoryScope(root),
            inspection = gitInspection(operation, a);
          if (!repo) fail('repository_missing');
          if (!inspection) fail('git_operation');
          for (const p of inspection.paths) {
            if (!p || p.startsWith('-') || /[\0:*?\[\]{}]/.test(p)) fail('git_pathspec');
            const resolved = await target(p, root, 'list');
            if (!within(resolved, repo.root)) fail('git_pathspec');
          }
          // Inspect fsmonitor configuration through the already trusted Git binary.
          const { execFile } = await import('node:child_process');
          const home = host.runtimeEnvironment.HOME ?? process.env.HOME,
            xdg = host.runtimeEnvironment.XDG_CONFIG_HOME ?? process.env.XDG_CONFIG_HOME;
          const rawConfig = await new Promise((resolve, reject) =>
            execFile(
              executable,
              ['--no-pager', 'config', '--null', '--list', '--includes', '--show-origin'],
              {
                cwd: root,
                env: { PATH: '/usr/bin:/bin', HOME: home, XDG_CONFIG_HOME: xdg },
                timeout: 300,
                maxBuffer: 262144,
                signal,
              },
              (error, stdout) => (error ? reject(error) : resolve(stdout)),
            ),
          );
          const fields = rawConfig.split('\0');
          if (fields.pop() !== '' || fields.length % 2) fail('git_config_origins');
          const values = [],
            inputs = new Set();
          const inputPath = async (value, base) => {
            if (!value || (value.startsWith('~') && !value.startsWith('~/'))) {
              gitInputsUnresolved = true;
              return;
            }
            try {
              inputs.add(
                await canonical(
                  value.startsWith('~/') ? path.join(home, value.slice(2)) : value,
                  base,
                ),
              );
            } catch {
              gitInputsUnresolved = true;
            }
          };
          for (const file of [
            path.join(home, '.gitconfig'),
            path.join(xdg ?? path.join(home, '.config'), 'git/config'),
            path.join(repo.gitDir, 'config'),
            path.join(repo.gitDir, 'config.worktree'),
            path.join(repo.commonDir, 'config'),
            '/etc/gitconfig',
            path.resolve(path.dirname(executable), '../etc/gitconfig'),
          ])
            await inputPath(file, root);
          for (let i = 0; i < fields.length; i += 2) {
            const origin = fields[i],
              entry = fields[i + 1];
            values.push(entry);
            if (!origin.startsWith('file:')) {
              gitInputsUnresolved = true;
              continue;
            }
            const originPath = path.resolve(root, origin.slice(5));
            await inputPath(originPath, root);
            const split = entry.indexOf('\n'),
              name = entry.slice(0, split).toLowerCase(),
              value = entry.slice(split + 1);
            if (/^(?:include|includeif\..+)\.path$/.test(name))
              await inputPath(value, path.dirname(originPath));
            if (['core.attributesfile', 'core.excludesfile'].includes(name)) {
              await inputPath(value, root);
              await inputPath(value, path.dirname(originPath));
            }
          }
          const conf = values.join('\0');
          for (const file of inputs) authority.add(file);
          for (const directory of [repo.root, repo.gitDir, repo.commonDir]) gitRoots.add(directory);
          if (conf.split('\0').some((x) => /^core\.fsmonitor\n(?!false$).+/i.test(x)))
            fail('git_fsmonitor');
          if (
            ['diff', 'show', 'log'].includes(operation) &&
            conf
              .split('\0')
              .some((x) => /^(?:diff\..*\.(?:command|textconv)|diff\.external)\n.+/i.test(x))
          )
            fail('git_external_diff');
          if (conf.split('\0').some((x) => /^log\.showsignature\n(?!false$).+/i.test(x)))
            fail('git_signature');
          add('git.read', repo.root, 'directory', {
            proof: digest({ repo, conf, inputs: [...inputs].sort() }),
          });
          return;
        }
        if (name === 'sqlite3') {
          const read = sqliteRead(args);
          await target(read.database, state.cwd, 'read');
          commands.at(-1).sqlite = {
            kind: read.kind,
            readOnly: true,
            safeMode: true,
            init: '/dev/null',
          };
          return;
        }
        if (name === 'sandbox-exec') {
          if (
            executable !== '/usr/bin/sandbox-exec' ||
            args[0] !== '-p' ||
            args[1] !== '(version 1)(allow default)(deny network*)' ||
            path.basename(args[2] ?? '') !== 'bd'
          )
            fail('sandbox_wrapper');
          return exec(args.slice(2), state, piped);
        }
        if (name === 'bd') {
          const a = [...args];
          let root = state.cwd,
            local = false,
            readOnly = false,
            off = false;
          while (typeof a[0] === 'string' && a[0].startsWith('-')) {
            const flag = a.shift();
            if (flag === '-C') root = await canonical(a.shift(), root);
            else if (flag === '--sandbox') local = true;
            else if (flag === '--readonly') readOnly = true;
            else if (flag === '--dolt-auto-commit' && a.shift() === 'off') off = true;
            else if (flag === '--actor' && /^[a-zA-Z0-9_-]+$/.test(a.shift() ?? '')) continue;
            else fail('beads_flags');
          }
          const metadata = JSON.parse(
            await readFile(path.join(root, '.beads/metadata.json'), 'utf8'),
          );
          const conf = await readFile(path.join(root, '.beads/config.yaml'), 'utf8');
          if (
            !local ||
            metadata.backend !== 'dolt' ||
            metadata.dolt_mode !== 'embedded' ||
            metadata.database !== 'dolt' ||
            !/^[A-Za-z0-9_-]+$/.test(metadata.dolt_database ?? '') ||
            conf
              .split(/\r?\n/)
              .map((x) => x.trim())
              .filter((x) => /^dolt\.local-only\s*:/.test(x))
              .join('\n') !== 'dolt.local-only: true' ||
            (await realpath(path.join(root, '.beads'))) !== path.join(root, '.beads') ||
            (await realpath(path.join(root, '.beads/embeddeddolt'))) !==
              path.join(root, '.beads/embeddeddolt')
          )
            fail('beads_backend');
          const op = a.shift();
          let category =
            ['show', 'list', 'ready', 'blocked', 'statuses', 'export'].includes(op) && readOnly
              ? 'beads.read'
              : op === 'update'
                ? 'beads.update'
                : ['create', 'close', 'dep'].includes(op)
                  ? 'beads.manage'
                  : null;
          if (
            !category ||
            (category !== 'beads.read' && !off) ||
            (op === 'dep' && !['add', 'list'].includes(a[0]))
          )
            fail('beads_operation');
          if (op === 'dep' && a[0] === 'list' && readOnly) category = 'beads.read';
          if (op === 'update' && a.some((v, i) => v === '--status' && a[i + 1] === 'closed'))
            category = 'beads.manage';
          for (let i = 0; i < a.length; i++) {
            if (typeof a[i] !== 'string') fail('beads_argument');
            if (!a[i].startsWith('-')) continue;
            const flag = a[i];
            if (flag === '--json') continue;
            if (
              ![
                '--status',
                '--type',
                '--title',
                '--description',
                '--metadata',
                '--notes',
                '--reason',
                '--exclude-type',
                '--limit',
                '--id',
              ].includes(flag) ||
              !a[++i]
            )
              fail('beads_flags');
            if (symbolic(a[i])) {
              if (flag !== '--metadata' || a[i].symbolic !== 'json-object') fail('beads_argument');
              continue;
            }
            if (typeof a[i] !== 'string' || a[i].startsWith('-')) fail('beads_flags');
            if (flag === '--metadata' && a[i].startsWith('@')) await target(a[i].slice(1), root);
          }
          authority.add(path.join(root, '.beads/metadata.json'));
          authority.add(path.join(root, '.beads/config.yaml'));
          if (category !== 'beads.read') mutation++;
          add(category, root, 'directory', { proof: digest({ metadata, conf }) });
          return category === 'beads.read' && a.includes('--json') ? 'json' : undefined;
        }
        if (/^python(?:3(?:\.\d+)?)?$/.test(name)) {
          const decodedPython = pythonInvocation(argv, {
            cwd: state.cwd,
            stdin: state.inputSource,
          });
          const pinnedPythonHelper =
            decodedPython.source?.kind === 'file' &&
            config.staticShell?.helpers?.some((p) => p.path === decodedPython.source.path);
          const legacyModuleArgs = args.filter(
            (value, index) => index >= args.findIndex((x) => !/^-[ISB]+$/.test(x)),
          );
          const knownPytest = legacyModuleArgs[0] === '-m' && legacyModuleArgs[1] === 'pytest';
          if (config.staticPython?.enabled && !knownPytest && !pinnedPythonHelper) {
            if (++pythonDepth > 4) fail('python_recursion_limit');
            const previousLocation = sourceLocation;
            const unresolved = (reason, extra = {}) => {
              complete = false;
              pythonUnresolved.push({ reason, ...extra, commandIndex: commands.length - 1 });
            };
            try {
              const identity = await commandHost.resolveExecutableIdentity(
                argv[0],
                !state.directProcess,
              );
              let stdin = state.inputSource;
              if (
                stdin === undefined &&
                state.inputFile &&
                decodedPython.reason === 'python_stdin_unresolved'
              ) {
                if (!state.inputFileFresh) fail('python_stdin_file_position');
                const helper = await readPythonHelper(state.inputFile);
                stdin = helper.body;
                authority.add(state.inputFile);
                snapshots.push({ pythonSource: state.inputFile, ...helper, body: undefined });
              }
              const invocation = pythonInvocation(argv, { cwd: state.cwd, stdin });
              if (invocation.startup?.required) {
                const entry = identity.path;
                const registered = config.staticPython.environments?.find(
                  (p) => p.interpreter.path === entry,
                );
                add(
                  'python.startup',
                  registered?.prefix ?? path.dirname(path.dirname(entry)),
                  'exact',
                );
              }
              if (!invocation.complete) {
                unresolved(invocation.reason);
                return;
              }
              let body = invocation.source.text,
                scriptPath;
              if (invocation.source.kind === 'file') {
                scriptPath = await target(invocation.source.path, state.cwd);
                if ([...changed.keys()].some((p) => within(scriptPath, p) || within(p, scriptPath)))
                  fail('python_helper_modified');
                const helper = await readPythonHelper(scriptPath);
                body = helper.body;
                authority.add(scriptPath);
                snapshots.push({ pythonSource: scriptPath, ...helper, body: undefined });
              }
              let profile;
              try {
                profile = await attestPythonEnvironment(
                  identity,
                  invocation,
                  config.staticPython,
                  signal,
                );
              } catch (e) {
                unresolved(e.message);
              }
              if (profile) {
                for (const pin of profile.files) {
                  authority.add(pin.path);
                  authority.add(pin.realpath);
                }
                for (const directory of profile.directories) globRoots.add(directory.realpath);
                snapshots.push({
                  pythonEnvironment: profile.interpreter.path,
                  prefix: profile.prefix,
                  version: profile.version,
                  fingerprint: digest(profile),
                });
              }
              const parserConfig = {
                ...config.staticPython.parser,
                ...(profile ? { interpreter: profile.interpreter } : {}),
              };
              const parserProfile =
                profile ??
                (await attestPythonEnvironment(
                  {
                    path: parserConfig.interpreter.path,
                    realpath: parserConfig.interpreter.realpath,
                  },
                  { isolation: { isolated: true, noSite: true, noBytecode: true } },
                  config.staticPython,
                  signal,
                ));
              for (const pin of parserProfile.files) {
                authority.add(pin.path);
                authority.add(pin.realpath);
              }
              for (const directory of parserProfile.directories) globRoots.add(directory.realpath);
              authority.add(parserConfig.path);
              const parsed = await parsePythonSource(body, parserConfig, signal);
              if (parsed.status !== 'parsed') {
                unresolved(parsed.reason);
                return;
              }
              if (profile && JSON.stringify(parsed.grammar) !== JSON.stringify(profile.version))
                unresolved('python_grammar_mismatch');
              snapshots.push({
                pythonSource: scriptPath ?? '<inline>',
                sha256: parsed.sourceSha256,
              });
              const effects = pythonEffects(parsed.ast, {
                cwd: state.cwd,
                scriptPath,
                source: scriptPath ?? '<inline>',
                argv: invocation.argv,
              });
              for (const issue of effects.unresolved) unresolved(issue.reason, issue);
              for (const effect of effects.effects) {
                sourceLocation = {
                  source: effect.source,
                  line: effect.line,
                  column: effect.column,
                  endLine: effect.endLine,
                };
                try {
                  if (effect.kind === 'import') {
                    if (effect.module !== 'os' && !effect.module?.startsWith('os.'))
                      add('python.import', effect.module ?? '<relative>', 'exact');
                    if (!profile?.modules?.[effect.module] || effect.level)
                      unresolved('python_import_unverified', sourceLocation);
                  } else if (effect.kind === 'file') {
                    if (
                      effect.operation === 'files.delete' &&
                      (
                        await lstat(effect.target).catch((e) => {
                          if (e.code !== 'ENOENT') throw e;
                        })
                      )?.isSymbolicLink()
                    )
                      unresolved('python_unlink_symlink', sourceLocation);
                    await target(
                      effect.target,
                      state.cwd,
                      effect.operation.slice('files.'.length),
                      effect.targetType,
                    );
                  } else if (effect.kind === 'command') {
                    const environment = effect.environment
                      ? { ...effect.environment }
                      : {
                          ...commandHost.runtimeEnvironment,
                          ...state.environment,
                        };
                    if (!Object.hasOwn(environment, 'PATH')) {
                      if (effect.shell || !profile?.defaultPath)
                        fail('python_default_path_unverified');
                      environment.PATH = profile.defaultPath;
                    }
                    const childHost = executableResolver(environment, config.staticShell);
                    const childState = {
                      cwd: effect.cwd,
                      vars: {},
                      arrays: {},
                      jsonFiles: {},
                      commandHost: childHost,
                      environment: effect.environment ?? state.environment,
                      inputSource: typeof effect.input === 'string' ? effect.input : undefined,
                      inputFile: effect.stdio.stdin?.file,
                      directProcess: !effect.shell,
                    };
                    if (effect.shell) {
                      const sh = await childHost.resolveExecutable('/bin/sh', false);
                      if (!sh) fail('python_child_shell_unverified');
                      authority.add(sh);
                      const childAst = await parseShell(
                        effect.command,
                        config.staticShell,
                        'posix',
                        signal,
                      );
                      await sequence(
                        childAst.Stmts,
                        [childState],
                        !!effect.stdio.stdin || effect.input !== undefined,
                      );
                    } else {
                      const childArgv = [...effect.argv];
                      if (childArgv[0].includes('/') && !path.isAbsolute(childArgv[0]))
                        childArgv[0] = path.resolve(effect.cwd, childArgv[0]);
                      await exec(
                        childArgv,
                        childState,
                        !!effect.stdio.stdin || effect.input !== undefined,
                      );
                    }
                  }
                } catch (e) {
                  unresolved(e.message, sourceLocation);
                }
              }
              return;
            } finally {
              pythonDepth--;
              sourceLocation = previousLocation;
            }
          }
          const a = [...args],
            flags = [];
          while (/^-[ISB]+$/.test(a[0] ?? '')) flags.push(a.shift());
          if (a[0] === '-m' && a[1] === 'pytest') {
            const tests = [];
            for (let i = 2; i < a.length; i++) {
              if (
                /^-[qvsx]+$/.test(a[i]) ||
                ['--no-header', '--disable-warnings', '--collect-only'].includes(a[i])
              )
                continue;
              if (/^--tb=(?:auto|long|short|line|native|no)$/.test(a[i])) continue;
              if (
                a[i] === '-W' &&
                /^(?:error|ignore|always|default|module|once)::(?:Warning|UserWarning|DeprecationWarning|RuntimeWarning|FutureWarning)$/.test(
                  a[i + 1] ?? '',
                )
              ) {
                i++;
                continue;
              }
              if (a[i] === '--basetemp' || a[i].startsWith('--basetemp=')) {
                const destination =
                  a[i] === '--basetemp' ? a[++i] : a[i].slice('--basetemp='.length);
                if (!destination || destination.startsWith('-')) fail('pytest_basetemp');
                // Pytest removes this directory before reuse. Read/write alone
                // cannot authorize that effect, even when tests are allowed.
                await target(destination, state.cwd, 'delete', 'directory');
                await target(destination, state.cwd, 'write', 'directory');
                continue;
              }
              if (a[i] === '-p' && a[++i] === 'no:cacheprovider') continue;
              if (a[i].startsWith('-') || /[\0*?]/.test(a[i])) fail('pytest_flags');
              const file = await canonical(a[i].split('::')[0], state.cwd);
              tests.push(file);
            }
            if (!tests.length) fail('pytest_targets');
            for (const file of tests) {
              let stat;
              try {
                stat = await lstat(file);
              } catch (error) {
                if (error.code !== 'ENOENT') throw error;
                // The runner may load configuration before rejecting this
                // selection. Require review, but retain subsequent commands
                // and the other cwd branch instead of aborting analysis.
                complete = false;
                shellUnresolved.push({
                  reason: 'pytest_target_missing',
                  message: `Test target is absent in this execution context: ${file}`,
                  target: file,
                  cwd: state.cwd,
                  ...(state.cdBranch ? { cdBranch: state.cdBranch } : {}),
                  commandIndex: commands.length - 1,
                });
              }
              add('tests.run', file, stat?.isDirectory() ? 'directory' : 'file', {
                runner: executable,
                description:
                  'Execute test code and its configuration in this checkout. Tests may have side effects.',
              });
            }
            return;
          }
          const name = a.shift(),
            pin = config.staticShell?.helpers?.find(
              (p) => p.path === path.resolve(state.cwd, name ?? ''),
            );
          if (!pin || !['I', 'S', 'B'].every((x) => flags.join('').includes(x)))
            fail('python_source');
          const resolved = await realpath(pin.path);
          const { sha256 } = await import('./shell-host.mjs');
          if (resolved !== pin.realpath || sha256(await readFile(resolved)) !== pin.sha256)
            fail('helper_changed');
          if ((!a.length && !piped) || a.some((x) => x.startsWith('-'))) fail('helper_arguments');
          await pathArgs(a, state);
          authority.add(pin.path);
          authority.add(resolved);
          add('tools.lint', resolved, 'file', { proof: pin.sha256 });
          return;
        }
        fail('unsupported_command');
      };
      const sequence = async (stmts, states, piped = false) => {
        for (const stmt of stmts ?? []) states = await walk(stmt, states, piped);
        return states;
      };
      const substitution = async (part, state) => {
        if (
          part.Backquotes ||
          part.TempFile ||
          part.ReplyVar ||
          part.Stmts?.length !== 1 ||
          part.Stmts[0].Cmd?.Type !== 'CallExpr'
        )
          fail('substitution_syntax');
        const before = mutation;
        const results = await sequence(part.Stmts, [
          {
            ...state,
            vars: { ...state.vars },
            arrays: { ...state.arrays },
            jsonFiles: { ...state.jsonFiles },
          },
        ]);
        if (mutation !== before) fail('substitution_write');
        if (!results.length || results.some((s) => !['json', 'json-object'].includes(s.outputKind)))
          fail('substitution_output');
        return {
          symbolic: results.every((s) => s.outputKind === 'json-object') ? 'json-object' : 'json',
        };
      };
      const walk = async (stmt, states, piped = false) => {
        if (!states.length) return [];
        if (++visits > 256 || states.length > 16 || items.size > 128) fail('analysis_limit');
        if (!stmt || stmt.Background || stmt.Coprocess || stmt.Disown || stmt.Negated)
          fail('unsupported_statement');
        states = states.map((s) => ({
          ...s,
          jsonFiles: { ...s.jsonFiles },
          inputKind: undefined,
          inputSource: undefined,
          inputFile: undefined,
          inputFileFresh: undefined,
          outputKind: undefined,
          outputPath: undefined,
        }));
        for (const r of stmt.Redirs ?? []) {
          if (
            r.Op === '>&' &&
            r.N?.Value === '2' &&
            r.Word?.Parts?.length === 1 &&
            r.Word.Parts[0]?.Value === '1'
          )
            continue;
          if (
            r.Op === '<<' &&
            !r.N &&
            r.Hdoc &&
            r.Word?.Parts?.length === 1 &&
            r.Word.Parts[0].Type === 'SglQuoted'
          ) {
            const body = (r.Hdoc.Parts ?? []).every((p) => p.Type === 'Lit')
              ? (r.Hdoc.Parts ?? []).map((p) => p.Value ?? '').join('')
              : undefined;
            for (const state of states) {
              state.inputKind = jsonKind(body);
              state.inputSource = body;
            }
            piped = true;
            continue;
          }
          if (
            !['>', '>>', '<'].includes(r.Op) ||
            r.Hdoc ||
            (r.N && !(r.Op === '<' ? ['0'] : ['1', '2']).includes(r.N.Value))
          )
            fail('redirection');
          const producer = r.Word?.Parts?.length === 1 && r.Word.Parts[0];
          if (
            r.Op === '<' &&
            (!r.N || r.N.Value === '0') &&
            producer?.Type === 'ProcSubst' &&
            producer.Op === '<('
          ) {
            for (const state of states)
              state.inputKind = (await substitution(producer, state)).symbolic;
            piped = true;
            continue;
          }
          for (const state of states) {
            const file = literal(r.Word, state.vars);
            if (file === '/dev/null') {
              const stat = await lstat(file);
              if (!stat.isCharacterDevice() || stat.uid !== 0 || (await realpath(file)) !== file)
                fail('null_device');
              snapshots.push({
                lexical: file,
                resolved: file,
                dev: stat.dev,
                ino: stat.ino,
                mode: stat.mode,
                rdev: stat.rdev,
              });
              if (!r.N || r.N.Value === '1') state.outputPath = undefined;
              continue;
            }
            const resolved = await target(file, state.cwd, r.Op === '<' ? 'read' : 'write');
            if (r.Op === '<') {
              state.inputFile = resolved;
              state.inputFileFresh = true;
            }
            if (r.Op !== '<') {
              for (const key of Object.keys(state.jsonFiles))
                if (within(key, resolved) || within(resolved, key)) delete state.jsonFiles[key];
              if (!r.N || r.N.Value === '1') state.outputPath = r.Op === '>' ? resolved : undefined;
            }
          }
          if (r.Op === '<') {
            piped = true;
            for (const state of states) state.inputKind = undefined;
          }
        }
        const cmd = stmt.Cmd;
        if (cmd?.Type === 'BinaryCmd') {
          if (cmd.Op === '|') {
            await walk(cmd.X, states, piped);
            await walk(cmd.Y, states, true);
            return states.map((s) => ({ ...s, exit: undefined }));
          }
          if (!['&&', '||'].includes(cmd.Op)) fail('shell_operator');
          const left = await walk(cmd.X, states, piped);
          const succeeds = left.filter((s) => s.exit !== false),
            fails = left.filter((s) => s.exit !== true);
          return cmd.Op === '&&'
            ? [
                ...fails.map((s) => ({ ...s, exit: false })),
                ...(await walk(cmd.Y, succeeds, piped)),
              ]
            : [
                ...succeeds.map((s) => ({ ...s, exit: true })),
                ...(await walk(cmd.Y, fails, piped)),
              ];
        }
        if (cmd?.Type === 'Block') return sequence(cmd.Stmts, states, piped);
        if (cmd?.Type === 'IfClause') {
          const condition = await sequence(cmd.Cond, states, piped);
          const yes = await sequence(
            cmd.Then,
            condition.filter((s) => s.exit !== false),
            piped,
          );
          const failed = condition.filter((s) => s.exit !== true);
          const no = !cmd.Else
            ? failed.map((s) => ({ ...s, exit: true }))
            : cmd.Else.Cond?.length
              ? await walk({ Cmd: { ...cmd.Else, Type: 'IfClause' } }, failed, piped)
              : await sequence(cmd.Else.Then, failed, piped);
          return [...yes, ...no];
        }
        if (
          cmd?.Type === 'ForClause' &&
          cmd.Loop?.Type === 'WordIter' &&
          cmd.Loop.Items?.length <= 16 &&
          !special.test(cmd.Loop.Name.Value)
        ) {
          if (states.some((s) => Object.hasOwn(s.arrays, cmd.Loop.Name.Value)))
            fail('shell_array_mutation');
          for (const value of cmd.Loop.Items) {
            states = states.map((s) => ({
              ...s,
              vars: { ...s.vars, [cmd.Loop.Name.Value]: literal(value, s.vars) },
            }));
            states = await sequence(cmd.Do, states, piped);
          }
          return states;
        }
        if (cmd?.Type !== 'CallExpr')
          fail('shell_syntax:' + (cmd?.Type ?? 'unknown'), {
            commandIndex: null,
            source: '<shell>',
            line: stmt.Pos?.Line,
            column: stmt.Pos?.Col,
          });
        const inline = !!cmd.Args?.length;
        if (cmd.Assigns?.length && !inline && stmt.Redirs?.length) fail('assignment_redirection');
        if (cmd.Assigns?.length && piped && !inline) fail('command_environment');
        const out = [];
        for (let state of states) {
          state = {
            ...state,
            vars: { ...state.vars },
            arrays: { ...state.arrays },
            exit: undefined,
          };
          const environment = {};
          for (const a of cmd.Assigns ?? []) {
            if (!nameRE.test(a.Name?.Value) || a.Append || a.Index) fail('shell_assignment');
            if (a.Array) {
              if (
                inline ||
                special.test(a.Name.Value) ||
                !a.Array.Elems?.length ||
                a.Array.Elems.length > 64
              )
                fail('shell_array');
              if (a.Array.Elems.some((e) => e.Index || !e.Value)) fail('shell_array');
              state.arrays[a.Name.Value] = a.Array.Elems.map((e) => literal(e.Value, state.vars));
              delete state.vars[a.Name.Value];
              continue;
            }
            if (Object.hasOwn(state.arrays, a.Name.Value)) fail('shell_array_mutation');
            const value = literal(a.Value, state.vars);
            if (inline) {
              if (
                !(
                  (a.Name.Value === 'PYTHONDONTWRITEBYTECODE' && value === '1') ||
                  (['LC_ALL', 'LANG'].includes(a.Name.Value) && value === 'C')
                )
              )
                fail('command_environment');
              environment[a.Name.Value] = value;
            } else {
              if (special.test(a.Name.Value)) fail('shell_assignment');
              state.vars[a.Name.Value] = value;
            }
          }
          if (cmd.Args?.length) {
            const argv = [];
            for (const w of cmd.Args) {
              const quote = w.Parts?.length === 1 && w.Parts[0],
                part =
                  quote?.Type === 'DblQuoted' &&
                  !quote.Dollar &&
                  quote.Parts?.length === 1 &&
                  quote.Parts[0];
              if (part?.Type === 'CmdSubst') argv.push(await substitution(part, state));
              else
                argv.push(
                  ...(arrayExpansion(w, state.arrays) ??
                    (await expandWord(w, state.vars, state.cwd, async (p) => {
                      globRoots.add(await target(p, state.cwd, 'list'));
                    }))),
                );
            }
            if (argv[0] === 'cd') {
              if (piped || argv.length !== 2 || argv[1].startsWith('-')) fail('cd_options');
              const next = await target(argv[1], state.cwd, 'access');
              if (next !== path.resolve(state.cwd, argv[1])) fail('logical_cwd');
              const cdBranch = { line: stmt.Pos?.Line, from: state.cwd, target: next };
              out.push({ ...state, exit: false, cdBranch: { ...cdBranch, outcome: 'failure' } });
              state = {
                ...state,
                cwd: next,
                exit: true,
                cdBranch: { ...cdBranch, outcome: 'success' },
              };
            } else {
              state.outputKind = await exec(
                argv,
                { ...state, ...(Object.keys(environment).length ? { environment } : {}) },
                piped,
              );
              if (stmt.Redirs?.some((r) => r.Op === '>&')) state.outputKind = undefined;
              if (state.outputKind && state.outputPath)
                state.jsonFiles[state.outputPath] = {
                  kind: state.outputKind,
                  generation: changed.get(state.outputPath),
                };
              if (state.outputPath || stmt.Redirs?.some((r) => r.Op === '>' || r.Op === '>>'))
                state.outputKind = undefined;
              if (!stmt.Redirs?.length && (argv[0] === 'true' || argv[0] === 'false'))
                state.exit = argv[0] === 'true';
            }
          } else if (!stmt.Redirs?.length) state.exit = true;
          out.push(state);
        }
        // Diagnostic provenance must not change which execution states merge.
        return [
          ...new Map(
            out.map((s) => {
              const { cdBranch, ...execution } = s;
              return [digest(execution), s];
            }),
          ).values(),
        ];
      };
      await sequence(ast.Stmts, [{ cwd, vars: {}, arrays: {}, jsonFiles: {} }]);
      const writes = [...items.values()].filter((g) => /\.(write|delete)$/.test(g.operation));
      if (
        writes.some((g) =>
          [...globRoots].some((root) => within(g.target, root) || within(root, g.target)),
        )
      )
        fail('glob_modified_in_command');
      if (
        writes.some((g) => [...authority].some((file) => within(file, g.target))) ||
        (gitRoots.size &&
          writes.some(
            (g) =>
              gitInputsUnresolved ||
              !scope.scratch ||
              !within(g.target, scope.scratch) ||
              [...gitRoots].some((root) => within(g.target, root) || within(root, g.target)),
          ))
      )
        fail('authority_modified_in_command');
      if (!items.size) add('shell.stream', cwd, 'directory');
    } else if (
      [
        'execute',
        'skill',
        'subagent',
        'question',
        'ask_coordinator',
        'answer_worker',
        'steer_worker',
        'wait_worker',
        'batch_status',
        'task_status',
        'task_result',
        'task_cancel',
        'wait_for_user',
        'approval_scratch',
      ].includes(request.action)
    ) {
      add('native.' + request.action, '*', 'any');
    } else {
      fail('unsupported_native_action');
    }
  } catch (error) {
    complete = false;
    reason = error.message;
    failureDiagnostic = error.diagnostic;
  }
  return {
    complete,
    reason: reason ?? shellUnresolved[0]?.reason ?? pythonUnresolved[0]?.reason,
    unresolved: complete
      ? []
      : [
          ...pythonUnresolved,
          ...shellUnresolved,
          ...(reason
            ? [
                {
                  reason,
                  commandIndex: commands.length ? commands.length - 1 : null,
                  ...failureDiagnostic,
                },
              ]
            : []),
        ],
    constraints,
    grants: [...items.values()],
    commands,
    snapshots,
    syntax,
    host: host?.fingerprint,
  };
}
