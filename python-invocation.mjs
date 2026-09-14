import path from 'node:path';

// Decode an already-normalized argv. Shell quoting and heredoc expansion belong
// to the shell parser. This function never probes or runs the requested Python.
export function pythonInvocation(argv, { cwd, stdin } = {}) {
  const unresolved = (reason) => ({ complete: false, reason });
  if (
    !path.isAbsolute(cwd ?? '') ||
    !Array.isArray(argv) ||
    !argv.length ||
    argv.length > 1024 ||
    argv.some((v) => typeof v !== 'string' || v.includes('\0')) ||
    argv.reduce((bytes, value) => bytes + Buffer.byteLength(value), 0) > 131072
  )
    return unresolved('python_invocation_input');
  if (!/^python(?:3(?:\.\d+)?)?$/.test(path.basename(argv[0])))
    return unresolved('python_invocation_executable');
  const flags = new Set();
  let mode,
    value,
    offset = 1;
  for (; offset < argv.length; offset++) {
    const argument = argv[offset];
    if (argument === '--') {
      offset++;
      if (offset === argv.length) return unresolved('python_interactive_input');
      mode = argv[offset] === '-' ? 'stdin' : 'file';
      value = argv[offset++];
      break;
    }
    if (argument === '-') {
      mode = 'stdin';
      value = argument;
      offset++;
      break;
    }
    if (!argument.startsWith('-')) {
      mode = 'file';
      value = argument;
      offset++;
      break;
    }
    if (argument.startsWith('--')) return unresolved('python_invocation_flag');
    for (let i = 1; i < argument.length; i++) {
      const flag = argument[i];
      if ('ISBEsPu'.includes(flag)) {
        flags.add(flag);
        continue;
      }
      if (flag !== 'c' && flag !== 'm') return unresolved('python_invocation_flag');
      mode = flag === 'c' ? 'inline' : 'module';
      value = argument.slice(i + 1) || argv[++offset];
      if (value === undefined) return unresolved('python_invocation_argument');
      break;
    }
    if (mode) {
      offset++;
      break;
    }
  }
  if (!mode) return unresolved('python_interactive_input');
  const isolation = {
    isolated: flags.has('I'),
    noSite: flags.has('S'),
    noBytecode: flags.has('B'),
    ignoreEnvironment: flags.has('I') || flags.has('E'),
    safePath: flags.has('I') || flags.has('P'),
    noUserSite: flags.has('I') || flags.has('s'),
  };
  const base = {
    // Preserve the venv entry point. A realpath alone merges different venvs
    // that symlink to the same base interpreter. The host must bind its identity.
    executable: argv[0],
    cwd,
    flags: [...flags].sort(),
    isolation,
    startup: { required: !(isolation.isolated && isolation.noSite) },
  };
  if (mode === 'module')
    return { ...base, ...unresolved('python_module_execution'), module: value };
  if (mode === 'stdin') {
    if (typeof stdin !== 'string') return { ...base, ...unresolved('python_stdin_unresolved') };
    value = stdin;
  }
  if (mode === 'file') {
    // Do not collapse symlink/.. traversal into a different filename.
    if (!value || value.split('/').includes('..'))
      return { ...base, ...unresolved('python_script_path') };
    return {
      ...base,
      complete: true,
      source: { kind: 'file', path: path.resolve(cwd, value) },
      argv: [value, ...argv.slice(offset)],
    };
  }
  if (Buffer.byteLength(value) > 65536 || value.includes('\0'))
    return { ...base, ...unresolved('python_source_limit') };
  return {
    ...base,
    complete: true,
    source: { kind: 'inline', text: value },
    argv: [mode === 'stdin' ? '-' : '-c', ...argv.slice(offset)],
  };
}
