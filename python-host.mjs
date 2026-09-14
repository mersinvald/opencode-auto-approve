import { spawn } from 'node:child_process';
import { open, realpath, readdir, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { sha256 } from './shell-host.mjs';

const sourceLimit = 65536,
  outputLimit = 2097152;
const fail = (reason) => {
  throw Error(reason);
};

// The driver runs only on a pinned interpreter from the configured profiles.
// Request source cannot select an unregistered parser executable.
export async function verifyPythonFile(file, maxBytes, executable = false) {
  if (!file || !path.isAbsolute(file.path ?? '') || !/^[a-f0-9]{64}$/.test(file.sha256 ?? ''))
    fail('python_parser_config');
  const actual = await realpath(file.path);
  if (actual !== (file.realpath ?? file.path)) fail('python_parser_path_changed');
  const handle = await open(
    actual,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile() ||
      ![0, process.getuid()].includes(stat.uid) ||
      stat.mode & 0o022 ||
      stat.size > maxBytes ||
      (executable && !(stat.mode & 0o111))
    )
      fail('python_parser_identity');
    // Bound reads even if the file grows after fstat. Do not allocate a full
    // interpreter image for each approval request.
    const hash = createHash('sha256'),
      buffer = Buffer.alloc(65536);
    let bytes = 0;
    while (bytes <= stat.size) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, stat.size + 1 - bytes),
        null,
      );
      if (!bytesRead) break;
      bytes += bytesRead;
      hash.update(buffer.subarray(0, bytesRead));
    }
    const after = await handle.stat();
    if (
      bytes !== stat.size ||
      after.size !== stat.size ||
      after.mtimeMs !== stat.mtimeMs ||
      after.ctimeMs !== stat.ctimeMs ||
      hash.digest('hex') !== file.sha256
    )
      fail('python_parser_changed');
  } finally {
    await handle.close();
  }
  return actual;
}
const verify = verifyPythonFile;

export async function readPythonHelper(file) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = await handle.stat();
    if (!st.isFile() || st.size > sourceLimit) fail('python_helper_identity');
    const buffer = Buffer.alloc(st.size + 1),
      { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const after = await handle.stat();
    if (
      bytesRead !== st.size ||
      after.size !== st.size ||
      after.mtimeMs !== st.mtimeMs ||
      after.ctimeMs !== st.ctimeMs
    )
      fail('python_helper_changed');
    const body = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, bytesRead));
    return { body, sha256: sha256(buffer.subarray(0, bytesRead)), dev: st.dev, ino: st.ino };
  } finally {
    await handle.close();
  }
}

export async function attestPythonEnvironment(identity, invocation, settings, signal) {
  if (!identity?.path || !identity.realpath) fail('python_environment_unbound');
  const entry = (await realpath(path.dirname(identity.path))) + '/' + path.basename(identity.path);
  const profile = settings.environments?.find(
    (p) => p.interpreter?.path === identity.path || p.interpreter?.path === entry,
  );
  if (!profile || profile.interpreter.realpath !== identity.realpath)
    fail('python_environment_unregistered');
  await verify(profile.interpreter, 256 * 1024 * 1024, true);
  if (
    !Array.isArray(profile.files) ||
    profile.files.length > 256 ||
    !Array.isArray(profile.absent) ||
    profile.absent.length > 256 ||
    !Array.isArray(profile.directories) ||
    profile.directories.length > 128
  )
    fail('python_environment_profile');
  for (const pin of profile.files) {
    signal?.throwIfAborted();
    await verify(pin, 16 * 1024 * 1024);
  }
  for (const file of profile.absent) {
    try {
      await lstat(file);
      fail('python_environment_changed');
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
  }
  for (const directory of profile.directories) {
    if (
      (await realpath(directory.path)) !== directory.realpath ||
      JSON.stringify((await readdir(directory.path)).sort()) !== JSON.stringify(directory.entries)
    )
      fail('python_environment_changed');
  }
  if (!invocation.isolation.isolated || !invocation.isolation.noSite)
    fail('python_startup_analysis_required');
  if (!invocation.isolation.noBytecode) fail('python_bytecode_analysis_required');
  return profile;
}

export async function parsePythonSource(source, parser, signal) {
  if (
    typeof source !== 'string' ||
    Buffer.byteLength(source) > sourceLimit ||
    source.includes('\0')
  )
    fail('python_source_limit');
  signal?.throwIfAborted();
  const driver = await verify(parser, sourceLimit);
  await verify(parser.interpreter, 256 * 1024 * 1024, true);
  signal?.throwIfAborted();
  const result = await new Promise((resolve, reject) => {
    let done = false,
      used = 0;
    const chunks = [];
    const proc = spawn(parser.interpreter.path, ['-I', '-S', '-B', driver], {
      cwd: path.dirname(driver),
      env: { PATH: '/usr/bin:/bin' },
      stdio: ['pipe', 'pipe', 'ignore'],
      signal,
    });
    const finish = (error, result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (error) {
        proc.kill('SIGKILL');
        reject(error);
      } else resolve(result);
    };
    const timer = setTimeout(() => finish(Error('python_parse_timeout')), 1000);
    proc.on('error', (error) => finish(signal?.aborted ? error : Error('python_parser_start')));
    proc.stdin.on('error', () => finish(Error('python_parser_input')));
    proc.stdout.on('data', (chunk) => {
      used += chunk.length;
      if (used > outputLimit + 1) finish(Error('python_output_limit'));
      else chunks.push(chunk);
    });
    proc.on('close', (code) => {
      if (code !== 0) {
        finish(Error('python_parser_exit'));
        return;
      }
      try {
        finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        finish(Error('python_parser_response'));
      }
    });
    proc.stdin.end(source);
  });
  if (result?.version !== 1 || !['parsed', 'unresolved'].includes(result.status))
    fail('python_parser_response');
  if (
    result.status === 'parsed' &&
    (result.ast?._type !== 'Module' ||
      result.sourceSha256 !== sha256(source) ||
      !Number.isInteger(result.nodes) ||
      result.nodes > 8192 ||
      result.nodes < 1)
  )
    fail('python_parser_response');
  // Bind the output to the same trusted driver and interpreter after parsing.
  await verify(parser, sourceLimit);
  await verify(parser.interpreter, 256 * 1024 * 1024, true);
  signal?.throwIfAborted();
  return result;
}
