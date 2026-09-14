import { spawn } from 'node:child_process';
import { readFile, lstat, realpath, access, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { digest, redact } from './policy.mjs';

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const badEnv =
  /^(BASH_ENV|ENV|IFS|ZDOTDIR|CDPATH|SHELLOPTS|BASHOPTS|PS[0-4]|PROMPT_COMMAND|GCONV_PATH|LOCPATH|NLSPATH|LIBPATH|SHLIB_PATH|GREP_OPTIONS|GREP_COLORS|POSIXLY_CORRECT|LD_.*|DYLD_.*|BASH_FUNC_.*|GIT_.*|BEADS_.*|BD_.*|DOLT_.*|PERL5.*|PERLIO|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|PYTHONINSPECT|PYTEST_ADDOPTS|PYTEST_PLUGINS)$/;
const builtins = new Set(['true', 'false', 'pwd', 'printf', 'echo', 'test', '[', 'set']);
const unsafeEnvironment = (k, v) =>
  v &&
  badEnv.test(k) &&
  !(
    (k === 'GIT_PAGER' && v === 'cat') ||
    (['GIT_TERMINAL_PROMPT', 'GIT_OPTIONAL_LOCKS'].includes(k) && v === '0')
  );

export function captureShellRuntime(now = Date.now) {
  const entries = new Map(),
    active = new Map(),
    bindings = new Map();
  const key = (command, cwd) => digest({ command, cwd });
  const prune = () => {
    for (const [k, row] of entries)
      if (
        (!row.owner && now() - row.time > 10000) ||
        (row.owner && !active.has(row.owner) && now() - row.time > 30 * 60000)
      ) {
        entries.delete(k);
        bindings.delete(row.owner);
      }
  };
  const owners = (k) => [...active].filter(([, v]) => v === k).map(([id]) => id);
  return {
    begin(owner, command, cwd) {
      if (!owner || active.size >= 256) return;
      const k = key(command, cwd);
      active.set(owner, k);
      if (owners(k).length > 1 && entries.has(k)) entries.get(k).ambiguous = true;
    },
    capture(event) {
      prune();
      const k = key(event.command, event.cwd),
        old = entries.get(k),
        ids = owners(k);
      if (entries.size >= 256 && !old) return;
      // The shell hook has no tool ID. Only a unique active invocation can own it.
      const row = {
        time: now(),
        event: structuredClone(event),
        ambiguous: !!old || ids.length > 1,
        owner: ids.length === 1 ? ids[0] : null,
      };
      if (old) old.ambiguous = true;
      entries.set(k, row);
      if (row.owner) bindings.set(row.owner, row);
    },
    get(command, cwd, owner) {
      prune();
      const k = key(command, cwd),
        row = bindings.get(owner) ?? entries.get(k);
      if (!row || row.ambiguous || row.event.command !== command || row.event.cwd !== cwd)
        return null;
      if (row.owner && row.owner !== owner) return null;
      if (!row.owner) {
        if (!owner || now() - row.time > 10000 || (active.has(owner) && active.get(owner) !== k))
          return null;
        row.owner = owner;
        bindings.set(owner, row);
      }
      // Active tool lifetimes cover all native permission dialogs. Untracked
      // captures have a bounded recovery lifetime and cannot cross tool IDs.
      if (!active.has(owner) && now() - row.time > 30 * 60000) return null;
      return structuredClone(row.event);
    },
    release(command, cwd, owner) {
      const k = active.get(owner) ?? key(command, cwd);
      active.delete(owner);
      bindings.delete(owner);
      if (!owners(k).length) entries.delete(k);
    },
    clear() {
      entries.clear();
      active.clear();
      bindings.clear();
    },
  };
}

export async function attestRuntime(runtime, settings) {
  if (!runtime?.env || !path.isAbsolute(runtime.shell ?? '')) throw Error('unverified_shell');
  const shellPath = await realpath(runtime.shell);
  const nixZsh = /^\/nix\/store\/[a-z0-9]+-zsh-[^/]+\/bin\/zsh$/.test(shellPath);
  if (!['/bin/zsh', '/bin/bash'].includes(runtime.shell) && !nixZsh)
    throw Error('unverified_shell');
  if (nixZsh) {
    const stat = await lstat(shellPath);
    if (stat.uid !== 0 || stat.mode & 0o222 || !stat.isFile()) throw Error('unverified_shell');
    // Nix zsh has a store-specific global startup path. It must be absent or pinned.
    const global = path.join(path.dirname(path.dirname(shellPath)), 'etc/zshenv');
    for (const file of [global, global + '.zwc']) {
      try {
        await lstat(file);
        const pin = settings.zshStartup?.files?.find((p) => p.path === file);
        if (!pin || sha256(await readFile(file)) !== pin.sha256)
          throw Error('unverified_nix_startup');
      } catch (e) {
        if (e.code !== 'ENOENT') throw e;
      }
    }
  }
  if (Object.entries(runtime.env).some(([k, v]) => unsafeEnvironment(k, v)))
    throw Error('shell_environment');
  if (runtime.shell === '/bin/zsh' || nixZsh) {
    // zsh always reads startup files, including for -c. Pins cover the audited
    // local startup chain; a changed setup falls back to the model. Never
    // source these files or run an introspection shell during approval.
    const trust = settings.zshStartup;
    if (!trust?.files?.length || !trust.environment || !trust.absent)
      throw Error('unverified_startup');
    for (const [k, v] of Object.entries(trust.environment))
      if (runtime.env[k] !== v) throw Error('startup_environment');
    for (const pin of trust.files) {
      const stat = await lstat(await realpath(pin.path));
      if (
        !stat.isFile() ||
        stat.size > 65536 ||
        stat.mode & 0o022 ||
        sha256(await readFile(pin.path)) !== pin.sha256
      )
        throw Error('startup_changed');
    }
    for (const file of trust.absent) {
      try {
        await lstat(file);
        throw Error('startup_changed');
      } catch (e) {
        if (e.code !== 'ENOENT') throw e;
      }
    }
  }
  return {
    ...executableResolver(runtime.env, settings),
    fingerprint: digest({ runtime, shellPath }),
  };
}

export function executableResolver(environment, settings) {
  if (Object.entries(environment).some(([k, v]) => unsafeEnvironment(k, v)))
    throw Error('shell_environment');
  const resolveExecutable = async (name, useBuiltins = true) => {
    if (useBuiltins && builtins.has(name)) return { path: name, realpath: 'builtin:' + name };
    const search = name.includes('/')
      ? [name]
      : (environment.PATH ?? '').split(':').map((p) => path.join(p, name));
    for (const candidate of search) {
      if (!path.isAbsolute(candidate)) throw Error('relative_executable');
      try {
        await access(candidate, constants.X_OK);
      } catch (e) {
        if (['ENOENT', 'EACCES', 'ENOTDIR'].includes(e.code)) continue;
        throw e;
      }
      const target = await realpath(candidate),
        stat = await lstat(target);
      const pythonName = (n) => /^python(?:3(?:\.\d+)?)?$/.test(n);
      const pin = settings.executables?.find(
        (p) =>
          (p.path === candidate || p.realpath === target) &&
          (p.name === path.basename(name) ||
            (pythonName(p.name) && pythonName(path.basename(name)))),
      );
      if (
        pin &&
        target === pin.realpath &&
        stat.isFile() &&
        !(stat.mode & 0o022) &&
        stat.size < 256 * 1024 * 1024 &&
        sha256(await readFile(target)) === pin.sha256
      )
        return { path: candidate, realpath: target };
      // A writable wrapper earlier in PATH must not be skipped to find a later
      // trusted binary. Nix store binaries are immutable and root-owned.
      if (
        !stat.isFile() ||
        stat.uid !== 0 ||
        stat.mode & 0o022 ||
        !/^(\/(usr\/)?bin\/|\/nix\/store\/[^/]+\/bin\/)/.test(target) ||
        (path.basename(target) !== path.basename(name) &&
          !(
            ['/bin/sh', '/usr/bin/sh'].includes(candidate) &&
            [
              '/bin/sh',
              '/usr/bin/sh',
              '/bin/dash',
              '/usr/bin/dash',
              '/bin/bash',
              '/usr/bin/bash',
            ].includes(target)
          ))
      )
        return null;
      const file = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const header = Buffer.alloc(4);
        await file.read(header, 0, 4, 0);
        if (
          ![
            '7f454c46',
            'cffaedfe',
            'cefaedfe',
            'feedfacf',
            'feedface',
            'cafebabe',
            'bebafeca',
            'cafebabf',
            'bfbafeca',
          ].includes(header.toString('hex'))
        )
          return null;
      } finally {
        await file.close();
      }
      return { path: candidate, realpath: target };
    }
    return null;
  };
  // Reuse verified identities only within this analysis. Revalidation hashes again.
  const verified = new Map();
  return {
    resolveExecutableIdentity: (name, useBuiltins = true) => {
      const key = JSON.stringify([name, useBuiltins]);
      if (!verified.has(key)) verified.set(key, resolveExecutable(name, useBuiltins));
      return verified.get(key);
    },
    resolveExecutable: async (name, useBuiltins = true) => {
      const key = JSON.stringify([name, useBuiltins]);
      if (!verified.has(key)) verified.set(key, resolveExecutable(name, useBuiltins));
      return (await verified.get(key))?.realpath ?? null;
    },
    runtimeEnvironment: environment,
    fingerprint: digest({ environment }),
  };
}

export async function parseShell(command, settings, dialect, signal) {
  if (typeof command !== 'string' || Buffer.byteLength(command) > 32768 || command.includes('\0'))
    throw Error('input_limit');
  const parser = settings.parser;
  if (!parser || !path.isAbsolute(parser.path) || !/^[a-f0-9]{64}$/.test(parser.sha256))
    throw Error('parser_missing');
  const stat = await lstat(parser.path);
  if (
    !stat.isFile() ||
    stat.uid !== process.getuid() ||
    stat.mode & 0o022 ||
    stat.size > 16 * 1024 * 1024 ||
    sha256(await readFile(parser.path)) !== parser.sha256
  )
    throw Error('parser_changed');
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const proc = spawn(parser.path, [dialect], {
      stdio: ['pipe', 'pipe', 'ignore'],
      shell: false,
      env: { PATH: '/usr/bin:/bin', GOMEMLIMIT: '64MiB', GOMAXPROCS: '1' },
      signal,
    });
    const chunks = [];
    let bytes = 0;
    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      reject(Error('parser_timeout'));
    }, 500);
    proc.stdout.on('data', (data) => {
      bytes += data.length;
      if (bytes > 2 * 1024 * 1024) {
        proc.kill('SIGKILL');
        reject(Error('ast_limit'));
      } else chunks.push(data);
    });
    proc.stdin.on('error', () => {});
    proc.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    proc.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(Error('parse_failed'));
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Error('invalid_ast'));
      }
    });
    proc.stdin.end(command);
  });
}

// Only the analyzer can call this after proving every argument and target of a
// supported read-only predicate. Execute the binary directly, never shell text.
export function probeReadCondition({ executable, args, cwd }, signal) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve({ exitCode: null, outcome: 'cancelled' });
    const child = spawn(executable, args, {
      cwd,
      stdio: 'ignore',
      shell: false,
      env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' },
      signal,
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, 200);
    const done = (code) => {
      clearTimeout(timer);
      resolve({
        exitCode: Number.isInteger(code) ? code : null,
        outcome: timedOut ? 'timeout' : Number.isInteger(code) ? 'observed' : 'unavailable',
        observedAt: new Date().toISOString(),
        locale: 'C',
      });
    };
    child.on('error', () => done(null));
    child.on('close', done);
  });
}
