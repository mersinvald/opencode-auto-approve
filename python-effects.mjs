import path from 'node:path';

// Semantic front end. No code, imports, commands or file contents
// are evaluated here. These effects still need runtime/source binding and the
// existing canonical-path + grant gate before they can authorize anything.
const UNKNOWN = Symbol('unknown');
const tagged = (kind, value) => ({ kind, value });
const builtin = new Set([
  'open',
  'print',
  'str',
  'bytes',
  'len',
  'bool',
  'int',
  'repr',
  'range',
  'sorted',
  'list',
]);
const isUnknown = (v) => v === UNKNOWN;
const hasParent = (value) => typeof value === 'string' && value.split('/').includes('..');
const string = (v) => (typeof v === 'string' ? v : v?.kind === 'path' ? v.value : null);
const openModes = /^(?:[rwax](?:[bt]?\+?|\+[bt]?)|[rwax]\+[bt]?)$/;
const maxString = 65536,
  maxValues = 256;
const knownReferences = new Set([
  'os.path',
  'os.getcwd',
  'os.chdir',
  'os.system',
  'os.path.join',
  'os.path.abspath',
  'os.path.dirname',
  'os.path.basename',
  'os.remove',
  'os.unlink',
  'os.rmdir',
  'os.mkdir',
  'os.listdir',
  'os.stat',
  'os.path.exists',
  'os.path.isfile',
  'os.path.isdir',
  'pathlib.Path',
  'pathlib.PosixPath',
  'pathlib.PurePath',
  'pathlib.PurePosixPath',
  'subprocess.run',
  'subprocess.call',
  'subprocess.check_call',
  'subprocess.check_output',
  'io.open',
  'hashlib.sha256',
  'json.loads',
]);
// Path objects keep their lexical path. They are resolved against cwd only
// when used, including after os.chdir(). Parent traversal stays unresolved.
const joinPath = (...parts) => {
  let result = '';
  for (const part of parts)
    result = part.startsWith('/') ? part : result ? result + '/' + part : part;
  return path.posix.normalize(result || '.').replace(/\/$/, '') || '/';
};
const textOptions = (kwargs) =>
  (kwargs.encoding == null ||
    (typeof kwargs.encoding === 'string' &&
      ['utf8', 'utf-8', 'utf_8', 'ascii', 'latin1', 'latin-1'].includes(
        kwargs.encoding.toLowerCase(),
      ))) &&
  (kwargs.errors == null ||
    [
      'strict',
      'ignore',
      'replace',
      'backslashreplace',
      'surrogateescape',
      'surrogatepass',
    ].includes(kwargs.errors)) &&
  (kwargs.newline == null || ['', '\n', '\r', '\r\n'].includes(kwargs.newline));

export function pythonEffects(
  tree,
  { cwd, source = '<inline>', scriptPath, argv = [], globResults = {} } = {},
) {
  if (!path.isAbsolute(cwd ?? '') || tree?._type !== 'Module') throw Error('python_effect_input');
  const effects = [],
    unresolved = [];
  let env = new Map();
  let moduleEnv = env;
  let currentDirectory = cwd,
    visits = 0,
    callDepth = 0,
    branchCount = 0;
  env.set('__file__', scriptPath ?? UNKNOWN);
  env.set('__name__', '__main__');
  const location = (node) => ({
    source,
    line: node.lineno,
    column: node.col_offset,
    endLine: node.end_lineno,
  });
  const unknown = (node, reason) => {
    if (unresolved.length < 128) unresolved.push({ ...location(node), reason });
    return UNKNOWN;
  };
  const effect = (node, data) =>
    effects.length < 512
      ? effects.push({ ...location(node), ...data })
      : unknown(node, 'python_effect_limit');
  const pathValue = (node, parts, kind = 'path') => {
    if (parts.reduce((size, part) => size + part.length + 1, 0) > maxString)
      return unknown(node, 'python_value_limit');
    return tagged(kind, joinPath(...parts));
  };
  const filename = (node, raw) => {
    const value = string(raw);
    if (
      value === null ||
      !value ||
      value.length > maxString ||
      hasParent(value) ||
      /[\0\r\n]/.test(value)
    )
      return unknown(node, 'python_dynamic_path');
    if (!path.isAbsolute(value) && typeof currentDirectory !== 'string')
      return unknown(node, 'python_dynamic_cwd');
    return path.resolve(typeof currentDirectory === 'string' ? currentDirectory : '/', value);
  };
  const file = (node, operation, raw, targetType) => {
    const target = filename(node, raw);
    if (isUnknown(target)) return UNKNOWN;
    effect(node, { kind: 'file', operation, target, ...(targetType ? { targetType } : {}) });
    return target;
  };
  const opened = (node, raw, mode = 'r', kwargs = {}) => {
    if (
      typeof mode !== 'string' ||
      !openModes.test(mode) ||
      (kwargs.opener !== undefined && kwargs.opener !== null) ||
      (kwargs.closefd !== undefined && kwargs.closefd !== true) ||
      (kwargs.buffering !== undefined && typeof kwargs.buffering !== 'bigint') ||
      !textOptions(kwargs)
    )
      return unknown(node, 'python_open_mode_or_opener');
    const target = filename(node, raw);
    if (isUnknown(target)) return UNKNOWN;
    if (mode[0] === 'r' || mode.includes('+')) file(node, 'files.read', target);
    if (mode[0] !== 'r' || mode.includes('+')) file(node, 'files.write', target);
    return tagged('file', { target, mode });
  };
  const argsOf = (node) => {
    const args = node.args.map(evaluate),
      kwargs = Object.create(null);
    if (node.args.some((a) => a._type === 'Starred') || node.keywords.some((k) => k.arg === null))
      unknown(node, 'python_dynamic_arguments');
    for (const keyword of node.keywords) kwargs[keyword.arg] = evaluate(keyword.value);
    return { args, kwargs };
  };
  const keysOnly = (kwargs, keys) => Object.keys(kwargs).every((k) => keys.includes(k));
  const command = (node, name, args, kwargs) => {
    const system = name === 'os.system';
    if (
      !keysOnly(
        kwargs,
        system
          ? []
          : [
              'args',
              'cwd',
              'shell',
              'check',
              'text',
              'encoding',
              'errors',
              'timeout',
              'capture_output',
              'stdin',
              'stdout',
              'stderr',
              'input',
              'env',
              'universal_newlines',
            ],
      )
    )
      return unknown(node, 'python_process_options');
    if (args.length > 1 || (args.length && Object.hasOwn(kwargs, 'args')))
      return unknown(node, 'python_process_arguments');
    if (!textOptions(kwargs)) return unknown(node, 'python_codec_or_error_handler');
    if (
      ['check', 'text', 'capture_output', 'universal_newlines'].some(
        (k) => kwargs[k] != null && typeof kwargs[k] !== 'boolean',
      ) ||
      (kwargs.timeout != null &&
        typeof kwargs.timeout !== 'bigint' &&
        !(kwargs.timeout?.kind === 'data' && kwargs.timeout.value === 'float'))
    )
      return unknown(node, 'python_process_option_protocol');
    const value = args[0] ?? kwargs.args,
      shell = system ? true : (kwargs.shell ?? false);
    if (typeof shell !== 'boolean') return unknown(node, 'python_dynamic_shell');
    const childCwd = kwargs.cwd == null ? currentDirectory : filename(node, kwargs.cwd);
    if (isUnknown(childCwd)) return unknown(node, 'python_dynamic_cwd');
    let commandText, commandArgv;
    if (shell) {
      if (typeof value !== 'string') return unknown(node, 'python_shell_arguments');
      commandText = value;
    } else {
      commandArgv =
        typeof value === 'string'
          ? [value]
          : value?.kind === 'sequence'
            ? value.value.map(string)
            : null;
      if (!commandArgv?.length || commandArgv.some((v) => v === null || v.includes('\0')))
        return unknown(node, 'python_dynamic_argv');
    }
    let environment;
    if (kwargs.env != null) {
      if (
        kwargs.env?.kind !== 'mapping' ||
        [...kwargs.env.value].some(([k, v]) => typeof k !== 'string' || typeof v !== 'string')
      )
        return unknown(node, 'python_dynamic_environment');
      environment = Object.fromEntries(kwargs.env.value);
    }
    const stdio = {};
    for (const key of ['stdin', 'stdout', 'stderr']) {
      const value = kwargs[key];
      if (value == null) continue;
      if (value?.kind === 'file') stdio[key] = { file: value.value.target, mode: value.value.mode };
      else if (
        value?.kind === 'constant' &&
        ['subprocess.PIPE', 'subprocess.DEVNULL', 'subprocess.STDOUT'].includes(value.value)
      )
        stdio[key] = value.value;
      else return unknown(node, 'python_process_stdio');
    }
    if (Object.hasOwn(kwargs, 'input') && kwargs.input != null && typeof kwargs.input !== 'string')
      unknown(node, 'python_dynamic_process_input');
    effect(node, {
      kind: 'command',
      argv: commandArgv,
      command: commandText,
      shell,
      cwd: childCwd,
      ...(environment ? { environment } : {}),
      stdio,
      ...(Object.hasOwn(kwargs, 'input')
        ? { input: typeof kwargs.input === 'string' ? kwargs.input : { unresolved: true } }
        : {}),
    });
    return tagged('process-result', null);
  };
  const call = (node) => {
    const fn = evaluate(node.func),
      { args, kwargs } = argsOf(node);
    if (fn?.kind === 'function') return invokeFunction(node, fn.value, args, kwargs);
    if (fn?.kind === 'method') {
      const { receiver, name } = fn.value;
      if (receiver?.kind === 'path') {
        if (name === 'glob' && args.length === 1 && !Object.keys(kwargs).length) {
          const pattern = args[0];
          if (
            typeof pattern !== 'string' ||
            !pattern ||
            pattern.length > 128 ||
            /[\/\\\[\]\x00-\x1f]/.test(pattern) ||
            pattern.includes('**') ||
            ['.', '..'].includes(pattern)
          )
            return unknown(node, 'python_glob_pattern');
          const target = filename(node, receiver);
          if (target === UNKNOWN) return UNKNOWN;
          const key = JSON.stringify([target, pattern]);
          effect(node, { kind: 'glob', target, pattern, key });
          if (!Object.hasOwn(globResults, key)) return unknown(node, 'python_glob_pending');
          return tagged(
            'sequence',
            globResults[key].map((p) => tagged('path', p)),
          );
        }
        if (
          ['read_text', 'read_bytes'].includes(name) &&
          !args.length &&
          keysOnly(kwargs, ['encoding', 'errors'])
        ) {
          if (!textOptions(kwargs)) return unknown(node, 'python_codec_or_error_handler');
          file(node, 'files.read', receiver);
          return tagged('data', name === 'read_bytes' ? 'bytes' : 'str');
        }
        if (
          ['write_text', 'write_bytes'].includes(name) &&
          args.length === 1 &&
          keysOnly(kwargs, ['encoding', 'errors', 'newline'])
        ) {
          if (!textOptions(kwargs)) return unknown(node, 'python_codec_or_error_handler');
          file(node, 'files.write', receiver);
          return tagged('data', 'int');
        }
        if (
          name === 'open' &&
          args.length <= 1 &&
          keysOnly(kwargs, ['mode', 'buffering', 'encoding', 'errors', 'newline'])
        )
          return opened(node, receiver, args[0] ?? kwargs.mode ?? 'r', kwargs);
        if (
          name === 'joinpath' &&
          !Object.keys(kwargs).length &&
          args.every((a) => string(a) !== null && !hasParent(string(a)))
        )
          return pathValue(node, [receiver.value, ...args.map(string)]);
        if (
          ['exists', 'is_file', 'is_dir', 'stat'].includes(name) &&
          !args.length &&
          !Object.keys(kwargs).length
        ) {
          file(node, 'files.read', receiver);
          return tagged('data', name === 'stat' ? 'stat' : 'bool');
        }
        if (name === 'unlink' && !args.length && keysOnly(kwargs, ['missing_ok'])) {
          if (kwargs.missing_ok !== undefined && typeof kwargs.missing_ok !== 'boolean')
            return unknown(node, 'python_file_option_protocol');
          file(node, 'files.delete', receiver);
          return null;
        }
        if (
          name === 'mkdir' &&
          !args.length &&
          keysOnly(kwargs, ['parents', 'exist_ok', 'mode']) &&
          (kwargs.parents === undefined || kwargs.parents === false)
        ) {
          if (
            (kwargs.mode !== undefined && typeof kwargs.mode !== 'bigint') ||
            (kwargs.exist_ok !== undefined && typeof kwargs.exist_ok !== 'boolean')
          )
            return unknown(node, 'python_file_option_protocol');
          file(node, 'files.write', receiver, 'directory');
          return null;
        }
      }
      if (
        receiver?.kind === 'file' &&
        [
          'read',
          'readline',
          'readlines',
          'write',
          'writelines',
          'flush',
          'close',
          'seek',
          'tell',
        ].includes(name)
      ) {
        if (!keysOnly(kwargs, [])) return unknown(node, 'python_file_arguments');
        const text = (v) =>
          typeof v === 'string' ||
          (v?.kind === 'data' && ['str', 'bytes', 'read_text', 'read_bytes'].includes(v.value));
        const integer = (v) => typeof v === 'bigint';
        if (
          (['read', 'readline', 'readlines'].includes(name) &&
            (args.length > 1 || !args.every(integer))) ||
          (['flush', 'close', 'tell'].includes(name) && args.length) ||
          (name === 'write' && (args.length !== 1 || !text(args[0]))) ||
          (name === 'writelines' &&
            (args.length !== 1 || args[0]?.kind !== 'sequence' || !args[0].value.every(text))) ||
          (name === 'seek' && (args.length < 1 || args.length > 2 || !args.every(integer)))
        )
          return unknown(node, 'python_file_argument_protocol');
        return tagged('data', ['write', 'seek', 'tell'].includes(name) ? 'int' : 'str');
      }
      if (
        receiver?.kind === 'hash' &&
        ['hexdigest', 'digest'].includes(name) &&
        !args.length &&
        !Object.keys(kwargs).length
      )
        return tagged('data', name === 'digest' ? 'bytes' : 'str');
      const textReceiver =
        typeof receiver === 'string' || (receiver?.kind === 'data' && receiver.value === 'str');
      if (textReceiver) {
        if (
          name === 'encode' &&
          args.length <= 1 &&
          keysOnly(kwargs, ['encoding', 'errors']) &&
          textOptions({ ...kwargs, ...(args.length ? { encoding: args[0] } : {}) })
        )
          return tagged('data', 'bytes');
        if (name === 'splitlines' && !args.length && !Object.keys(kwargs).length)
          return typeof receiver === 'string'
            ? tagged(
                'sequence',
                receiver
                  ? receiver
                      .replace(/(?:\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029])$/, '')
                      .split(/\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]/)
                  : [],
              )
            : tagged('data', 'strings');
        if (name === 'join' && args.length === 1 && !Object.keys(kwargs).length) {
          const values = args[0];
          if (values?.kind === 'sequence' && values.value.every((v) => typeof v === 'string')) {
            if (typeof receiver !== 'string') return tagged('data', 'str');
            const size =
              values.value.reduce((n, v) => n + v.length, 0) +
              receiver.length * Math.max(0, values.value.length - 1);
            return size <= maxString
              ? values.value.join(receiver)
              : unknown(node, 'python_value_limit');
          }
          if (
            (values?.kind === 'data' && values.value === 'strings') ||
            (values?.kind === 'sequence' &&
              values.value.every(
                (v) => typeof v === 'string' || (v?.kind === 'data' && v.value === 'str'),
              ))
          )
            return tagged('data', 'str');
        }
      }
      if (receiver?.kind === 'mapping' && !args.length && !Object.keys(kwargs).length) {
        if (name === 'keys') return tagged('sequence', [...receiver.value.keys()]);
        if (name === 'values') return tagged('sequence', [...receiver.value.values()]);
        if (name === 'items')
          return tagged(
            'sequence',
            [...receiver.value].map((v) => tagged('sequence', v)),
          );
      }
      return unknown(node, 'python_unknown_method:' + name);
    }
    const name = fn?.kind === 'reference' ? fn.value : null;
    if (!name) return unknown(node, 'python_unknown_callable');
    if (
      name === 'hashlib.sha256' &&
      args.length === 1 &&
      !Object.keys(kwargs).length &&
      args[0]?.kind === 'data' &&
      args[0].value === 'bytes'
    )
      return tagged('hash', 'sha256');
    if (
      name === 'json.loads' &&
      args.length === 1 &&
      !Object.keys(kwargs).length &&
      (typeof args[0] === 'string' ||
        (args[0]?.kind === 'data' && ['str', 'bytes'].includes(args[0].value)))
    )
      return tagged('data', 'json');
    if (
      ['list', 'sorted'].includes(name) &&
      args.length === 1 &&
      keysOnly(kwargs, name === 'sorted' ? ['reverse'] : []) &&
      (kwargs.reverse === undefined || typeof kwargs.reverse === 'boolean')
    ) {
      const value = args[0];
      if (value?.kind === 'data' && value.value === 'strings') return value;
      if (value?.kind === 'sequence') {
        if (name === 'list') return tagged('sequence', [...value.value]);
        const values = value.value;
        if (
          values.every((v) => typeof v === 'string' || (v?.kind === 'data' && v.value === 'str')) &&
          values.some((v) => typeof v !== 'string')
        )
          return tagged('data', 'strings');
        const kind = (v) =>
          typeof v === 'string'
            ? 'str'
            : typeof v === 'bigint'
              ? 'int'
              : v?.kind === 'path'
                ? 'path'
                : null;
        const category = values.length ? kind(values[0]) : 'str';
        if (category && values.every((v) => kind(v) === category)) {
          const cmp = (a, b) => {
            if (typeof a === 'bigint') return a < b ? -1 : a > b ? 1 : 0;
            const aa = [...a].map((c) => c.codePointAt(0)),
              bb = [...b].map((c) => c.codePointAt(0));
            for (let i = 0; i < Math.min(aa.length, bb.length); i++)
              if (aa[i] !== bb[i]) return aa[i] - bb[i];
            return aa.length - bb.length;
          };
          const compare = (a, b) => {
            if (category !== 'path') return cmp(a, b);
            const aa = a.value.split('/'),
              bb = b.value.split('/');
            for (let i = 0; i < Math.min(aa.length, bb.length); i++) {
              const c = cmp(aa[i], bb[i]);
              if (c) return c;
            }
            return aa.length - bb.length;
          };
          return tagged(
            'sequence',
            [...values].sort((a, b) => (kwargs.reverse ? -1 : 1) * compare(a, b)),
          );
        }
      }
      return unknown(node, 'python_sort_or_iter_protocol');
    }
    if (
      name === 'range' &&
      !Object.keys(kwargs).length &&
      args.length >= 1 &&
      args.length <= 3 &&
      args.every((x) => typeof x === 'bigint')
    ) {
      const [start, stop, step] =
        args.length === 1 ? [0n, args[0], 1n] : [args[0], args[1], args[2] ?? 1n];
      if (!step) return unknown(node, 'python_range_step');
      const values = [];
      for (let n = start; step > 0n ? n < stop : n > stop; n += step) {
        if (values.length >= 32) return unknown(node, 'python_loop_limit');
        values.push(n);
      }
      return tagged('sequence', values);
    }
    if (name === 'len' && args.length === 1 && !Object.keys(kwargs).length) {
      const value = args[0];
      if (typeof value === 'string') return BigInt([...value].length);
      if (value?.kind === 'sequence') return BigInt(value.value.length);
      if (value?.kind === 'mapping') return BigInt(value.value.size);
      return value?.kind === 'data' && ['str', 'bytes', 'strings', 'json'].includes(value.value)
        ? tagged('data', 'int')
        : unknown(node, 'python_len_protocol');
    }
    if (
      ['open', 'io.open'].includes(name) &&
      args.length <= 2 &&
      keysOnly(kwargs, [
        'file',
        'mode',
        'buffering',
        'encoding',
        'errors',
        'newline',
        'closefd',
        'opener',
      ])
    )
      return opened(node, args[0] ?? kwargs.file, args[1] ?? kwargs.mode ?? 'r', kwargs);
    if (
      ['pathlib.Path', 'pathlib.PosixPath', 'pathlib.PurePath', 'pathlib.PurePosixPath'].includes(
        name,
      ) &&
      !Object.keys(kwargs).length &&
      args.every((a) => string(a) !== null && !hasParent(string(a)))
    )
      return pathValue(node, args.map(string), name.includes('Pure') ? 'purepath' : 'path');
    if (name === 'os.getcwd' && !args.length && !Object.keys(kwargs).length)
      return currentDirectory;
    if (name === 'os.chdir' && args.length === 1 && !Object.keys(kwargs).length) {
      const target = file(node, 'files.access', args[0], 'directory');
      currentDirectory = target;
      return null;
    }
    if (
      name === 'os.path.join' &&
      args.length &&
      !Object.keys(kwargs).length &&
      args.every((a) => typeof a === 'string')
    ) {
      // Python join preserves a relative path and resets on an absolute part.
      if (args.reduce((size, part) => size + part.length + 1, 0) > maxString)
        return unknown(node, 'python_value_limit');
      let joined = args[0];
      for (const part of args.slice(1)) joined = path.isAbsolute(part) ? part : joined + '/' + part;
      return joined;
    }
    if (
      ['os.path.abspath', 'os.path.dirname', 'os.path.basename'].includes(name) &&
      args.length === 1 &&
      typeof args[0] === 'string' &&
      !Object.keys(kwargs).length
    ) {
      if (name.endsWith('abspath'))
        return hasParent(args[0])
          ? unknown(node, 'python_parent_path')
          : path.resolve(currentDirectory, args[0]);
      if (name.endsWith('basename')) return args[0].endsWith('/') ? '' : path.basename(args[0]);
      const end = args[0].lastIndexOf('/');
      return end < 0 ? '' : args[0].slice(0, end) || '/';
    }
    if (
      [
        'os.remove',
        'os.unlink',
        'os.rmdir',
        'os.mkdir',
        'os.listdir',
        'os.stat',
        'os.path.exists',
        'os.path.isfile',
        'os.path.isdir',
      ].includes(name) &&
      args.length === 1 &&
      !Object.keys(kwargs).length
    ) {
      const operation = ['os.remove', 'os.unlink', 'os.rmdir'].includes(name)
        ? 'files.delete'
        : name === 'os.mkdir'
          ? 'files.write'
          : name === 'os.listdir'
            ? 'files.list'
            : 'files.read';
      file(
        node,
        operation,
        args[0],
        ['os.rmdir', 'os.mkdir', 'os.listdir'].includes(name) ? 'directory' : undefined,
      );
      return tagged('data', 'result');
    }
    if (
      [
        'subprocess.run',
        'subprocess.call',
        'subprocess.check_call',
        'subprocess.check_output',
        'os.system',
      ].includes(name)
    )
      return command(node, name, args, kwargs);
    if (name === 'str' && args.length === 1 && !Object.keys(kwargs).length) {
      if (string(args[0]) !== null) return string(args[0]);
      if (typeof args[0] === 'bigint') return args[0].toString();
      return args[0]?.kind === 'data'
        ? tagged('data', 'str')
        : unknown(node, 'python_str_protocol');
    }
    if (name === 'print' && keysOnly(kwargs, ['sep', 'end', 'file', 'flush'])) {
      const printable = (v, depth = 0) =>
        depth < 16 &&
        v !== UNKNOWN &&
        (v === null ||
          ['string', 'bigint', 'boolean'].includes(typeof v) ||
          ['data', 'path'].includes(v?.kind) ||
          (v?.kind === 'sequence' && v.value.every((x) => printable(x, depth + 1))) ||
          (v?.kind === 'mapping' &&
            [...v.value].every(([k, x]) => printable(k, depth + 1) && printable(x, depth + 1))));
      if (kwargs.file != null && kwargs.file?.kind !== 'file')
        return unknown(node, 'python_print_destination');
      if (
        args.some((v) => !printable(v)) ||
        ['sep', 'end'].some((k) => kwargs[k] != null && typeof kwargs[k] !== 'string') ||
        (kwargs.flush !== undefined && typeof kwargs.flush !== 'boolean')
      )
        return unknown(node, 'python_print_protocol');
      return null;
    }
    return unknown(node, 'python_unknown_call:' + name);
  };
  const equal = (a, b) => {
    if (a === b) return true;
    if (a?.kind === 'path' && b?.kind === 'path') return a.value === b.value;
    if (a?.kind === 'reference' && b?.kind === 'reference') return a.value === b.value;
    return false;
  };
  const truth = (v, node = {}) => {
    if (v === null) return false;
    if (['boolean', 'string', 'bigint'].includes(typeof v)) return !!v;
    if (v?.kind === 'sequence') return !!v.value.length;
    if (v?.kind === 'mapping') return !!v.value.size;
    if (v?.kind === 'data' || v?.kind === 'path' || v === UNKNOWN) return UNKNOWN;
    return unknown(node, 'python_truth_protocol');
  };
  const fork = (node, yes, no) => {
    if (++branchCount > 32) return unknown(node, 'python_branch_limit');
    const parent = env,
      originalCwd = currentDirectory;
    env = new Map(parent);
    if (!callDepth) moduleEnv = env;
    const y = yes(),
      yenv = env,
      ycwd = currentDirectory;
    env = new Map(parent);
    if (!callDepth) moduleEnv = env;
    currentDirectory = originalCwd;
    const n = no(),
      nenv = env,
      ncwd = currentDirectory;
    env = parent;
    if (!callDepth) moduleEnv = env;
    for (const key of new Set([...yenv.keys(), ...nenv.keys()])) {
      const a = yenv.has(key) ? yenv.get(key) : UNKNOWN,
        b = nenv.has(key) ? nenv.get(key) : UNKNOWN;
      env.set(key, equal(a, b) ? a : UNKNOWN);
    }
    currentDirectory = ycwd === ncwd ? ycwd : UNKNOWN;
    return { yes: y, no: n };
  };
  function evaluate(node) {
    if (!node || ++visits > 8192) return unknown(node ?? {}, 'python_effect_limit');
    switch (node._type) {
      case 'Constant': {
        const v = node.value;
        if (v?.literal === 'int') return BigInt(v.value);
        if (v === null || ['string', 'boolean'].includes(typeof v)) return v;
        return tagged('data', v?.literal ?? 'constant');
      }
      case 'Name':
        return env.has(node.id)
          ? env.get(node.id)
          : builtin.has(node.id)
            ? tagged('reference', node.id)
            : UNKNOWN;
      case 'List':
      case 'Tuple':
        if (node.elts.length > maxValues) return unknown(node, 'python_value_limit');
        return tagged('sequence', node.elts.map(evaluate));
      case 'ListComp': {
        if (
          node.generators.length !== 1 ||
          node.generators[0].is_async ||
          node.generators[0].ifs.length
        )
          return unknown(node, 'python_comprehension_shape');
        const g = node.generators[0],
          values = evaluate(g.iter);
        if (values?.kind !== 'sequence' || values.value.length > 32)
          return unknown(node, 'python_dynamic_comprehension');
        const parent = env,
          result = [];
        env = new Map(parent);
        try {
          for (const value of values.value) {
            bind(g.target, value);
            result.push(evaluate(node.elt));
          }
        } finally {
          env = parent;
        }
        return tagged('sequence', result);
      }
      case 'Dict':
        if (node.keys.length > maxValues) return unknown(node, 'python_value_limit');
        if (node.keys.some((key) => key === null)) unknown(node, 'python_mapping_unpack');
        return tagged(
          'mapping',
          new Map(
            node.keys.map((key, i) => [key ? evaluate(key) : UNKNOWN, evaluate(node.values[i])]),
          ),
        );
      case 'Attribute': {
        const base = evaluate(node.value);
        if (base?.kind === 'reference') {
          const name = base.value + '.' + node.attr;
          if (['subprocess.PIPE', 'subprocess.DEVNULL', 'subprocess.STDOUT'].includes(name))
            return tagged('constant', name);
          if (name === 'sys.argv') return tagged('sequence', argv);
          return knownReferences.has(name)
            ? tagged('reference', name)
            : unknown(node, 'python_unknown_attribute:' + name);
        }
        if (base?.kind === 'path' && node.attr === 'parent')
          return tagged('path', path.dirname(base.value));
        if (base?.kind === 'path' && node.attr === 'name') return path.basename(base.value);
        if (
          base?.kind === 'process-result' &&
          ['stdout', 'stderr', 'returncode'].includes(node.attr)
        )
          return tagged('data', node.attr === 'returncode' ? 'int' : 'str');
        return tagged('method', { receiver: base, name: node.attr });
      }
      case 'BinOp': {
        const left = evaluate(node.left),
          right = evaluate(node.right);
        if (
          node.op._type === 'Div' &&
          left?.kind === 'path' &&
          string(right) !== null &&
          !hasParent(string(right))
        )
          return pathValue(node, [left.value, string(right)]);
        if (node.op._type === 'Add' && typeof left === 'string' && typeof right === 'string')
          return left.length + right.length <= maxString
            ? left + right
            : unknown(node, 'python_value_limit');
        if (node.op._type === 'Add' && left?.kind === 'sequence' && right?.kind === 'sequence')
          return left.value.length + right.value.length <= maxValues
            ? tagged('sequence', [...left.value, ...right.value])
            : unknown(node, 'python_value_limit');
        return unknown(node, 'python_unresolved_operator');
      }
      case 'Call':
        return call(node);
      case 'UnaryOp': {
        const v = evaluate(node.operand);
        if (node.op._type === 'Not') {
          const b = truth(v, node);
          return b === UNKNOWN ? UNKNOWN : !b;
        }
        if (typeof v === 'bigint' && node.op._type === 'USub') return -v;
        if (typeof v === 'bigint' && node.op._type === 'UAdd') return v;
        return unknown(node, 'python_unary_operator');
      }
      case 'Compare': {
        let left = evaluate(node.left),
          result = true;
        for (let i = 0; i < node.ops.length; i++) {
          const right = evaluate(node.comparators[i]),
            op = node.ops[i]._type;
          let part = UNKNOWN;
          if (
            [left, right].some(
              (v) =>
                v !== UNKNOWN &&
                v !== null &&
                typeof v === 'object' &&
                !['data', 'path'].includes(v.kind),
            )
          )
            unknown(node, 'python_comparison_protocol');
          if (
            (left === null || ['string', 'boolean', 'bigint'].includes(typeof left)) &&
            (right === null || ['string', 'boolean', 'bigint'].includes(typeof right))
          ) {
            if (['Eq', 'NotEq', 'Is', 'IsNot'].includes(op)) {
              if (
                ['Is', 'IsNot'].includes(op) &&
                left !== null &&
                right !== null &&
                typeof left !== 'boolean' &&
                typeof right !== 'boolean'
              )
                part = UNKNOWN;
              else if (['Is', 'IsNot'].includes(op))
                part = op === 'Is' ? left === right : left !== right;
              else {
                const a = typeof left === 'boolean' ? BigInt(left) : left,
                  b = typeof right === 'boolean' ? BigInt(right) : right;
                part = ['NotEq', 'IsNot'].includes(op) ? a !== b : a === b;
              }
            } else if (typeof left === 'bigint' && typeof right === 'bigint') {
              if (op === 'Lt') part = left < right;
              if (op === 'LtE') part = left <= right;
              if (op === 'Gt') part = left > right;
              if (op === 'GtE') part = left >= right;
            }
          }
          if (part === false) return false;
          if (part === UNKNOWN) result = UNKNOWN;
          left = right;
        }
        return result;
      }
      case 'BoolOp': {
        let value = evaluate(node.values[0]);
        for (const next of node.values.slice(1)) {
          const b = truth(value, node),
            and = node.op._type === 'And';
          if (b !== UNKNOWN && (and ? !b : b)) return value;
          if (b === UNKNOWN) {
            const result = fork(
              node,
              () => evaluate(next),
              () => value,
            );
            value = result !== UNKNOWN && equal(result.yes, result.no) ? result.yes : UNKNOWN;
          } else value = evaluate(next);
        }
        return value;
      }
      case 'IfExp': {
        const b = truth(evaluate(node.test), node);
        if (b !== UNKNOWN) return evaluate(b ? node.body : node.orelse);
        const result = fork(
          node,
          () => evaluate(node.body),
          () => evaluate(node.orelse),
        );
        return result !== UNKNOWN && equal(result.yes, result.no) ? result.yes : UNKNOWN;
      }
      case 'JoinedStr': {
        let out = '';
        for (const part of node.values) {
          let v;
          if (part._type === 'Constant') v = evaluate(part);
          else if (
            part._type === 'FormattedValue' &&
            !part.format_spec &&
            [-1, 115].includes(part.conversion)
          ) {
            v = evaluate(part.value);
            v = typeof v === 'bigint' ? String(v) : string(v);
          } else return unknown(node, 'python_string_format');
          if (typeof v !== 'string' || out.length + v.length > maxString)
            return unknown(node, 'python_dynamic_string');
          out += v;
        }
        return out;
      }
      case 'Subscript': {
        const value = evaluate(node.value);
        if (node.slice._type === 'Slice') {
          const bounds = ['lower', 'upper', 'step'].map((k) =>
            node.slice[k] ? evaluate(node.slice[k]) : null,
          );
          if (
            bounds.some(
              (v) => v !== null && (typeof v !== 'bigint' || v > 65536n || v < -65536n),
            ) ||
            (bounds[2] !== null && bounds[2] !== 1n)
          )
            return unknown(node, 'python_slice_protocol');
          if (value?.kind === 'data' && ['str', 'bytes'].includes(value.value)) return value;
          const seq =
            typeof value === 'string'
              ? [...value]
              : value?.kind === 'sequence'
                ? value.value
                : null;
          if (!seq) return unknown(node, 'python_slice_protocol');
          const sliced = seq.slice(
            bounds[0] === null ? 0 : Number(bounds[0]),
            bounds[1] === null ? seq.length : Number(bounds[1]),
          );
          return typeof value === 'string' ? sliced.join('') : tagged('sequence', sliced);
        }
        const index = evaluate(node.slice);
        if (
          value?.kind === 'sequence' &&
          typeof index === 'bigint' &&
          index >= 0n &&
          index < BigInt(value.value.length)
        )
          return value.value[Number(index)];
        if (value?.kind === 'mapping' && value.value.has(index)) return value.value.get(index);
        return UNKNOWN;
      }
      default:
        return unknown(node, 'python_expression:' + node._type);
    }
  }
  const bind = (node, value) => {
    if (node._type === 'Name') {
      env.set(node.id, value);
      return;
    }
    if (
      ['Tuple', 'List'].includes(node._type) &&
      value?.kind === 'sequence' &&
      node.elts.length === value.value.length
    ) {
      node.elts.forEach((target, i) => bind(target, value.value[i]));
      return;
    }
    unknown(node, 'python_assignment_target');
  };
  const block = (nodes) => {
    for (const node of nodes) {
      const flow = statement(node);
      if (flow) return flow;
    }
    return null;
  };
  const invokeFunction = (node, fn, args, kwargs) => {
    if (callDepth >= 8 || fn.node.args.vararg || fn.node.args.kwarg)
      return unknown(node, 'python_function_limit_or_arguments');
    const parameters = [...fn.node.args.posonlyargs, ...fn.node.args.args],
      names = parameters.map((x) => x.arg);
    if (
      args.length > names.length ||
      Object.keys(kwargs).some(
        (k) => !names.includes(k) && !fn.node.args.kwonlyargs.some((p) => p.arg === k),
      )
    )
      return unknown(node, 'python_function_arguments');
    const values = new Map();
    for (let i = 0; i < names.length; i++) {
      if (i < args.length && Object.hasOwn(kwargs, names[i]))
        return unknown(node, 'python_function_arguments');
      if (Object.hasOwn(kwargs, names[i]) && i < fn.node.args.posonlyargs.length)
        return unknown(node, 'python_function_arguments');
      const index = i - (names.length - fn.defaults.length);
      if (i >= args.length && !Object.hasOwn(kwargs, names[i]) && index < 0)
        return unknown(node, 'python_function_arguments');
      values.set(
        names[i],
        i < args.length
          ? args[i]
          : Object.hasOwn(kwargs, names[i])
            ? kwargs[names[i]]
            : fn.defaults[index],
      );
    }
    for (let i = 0; i < fn.node.args.kwonlyargs.length; i++) {
      const name = fn.node.args.kwonlyargs[i].arg;
      if (!Object.hasOwn(kwargs, name) && fn.node.args.kw_defaults[i] === null)
        return unknown(node, 'python_function_arguments');
      values.set(name, Object.hasOwn(kwargs, name) ? kwargs[name] : fn.kwdefaults[i]);
    }
    const parent = env;
    env = new Map(moduleEnv);
    for (const local of fn.locals) env.set(local, UNKNOWN);
    for (const [name, value] of values) env.set(name, value);
    callDepth++;
    try {
      const result = block(fn.node.body);
      return !result ? null : result.kind === 'return' ? result.value : UNKNOWN;
    } finally {
      callDepth--;
      env = parent;
    }
  };
  const statement = (node) => {
    if (++visits > 8192) {
      unknown(node, 'python_effect_limit');
      return;
    }
    if (node._type === 'Import' || node._type === 'ImportFrom') {
      for (const alias of node.names) {
        const module = node._type === 'Import' ? alias.name : node.module;
        effect(node, {
          kind: 'import',
          module,
          level: node.level ?? 0,
          names: node._type === 'ImportFrom' ? [alias.name] : [],
        });
        if (alias.name === '*' || node.level) {
          unknown(node, 'python_dynamic_import_binding');
          continue;
        }
        const name =
          alias.asname ?? (node._type === 'Import' ? alias.name.split('.')[0] : alias.name);
        const reference =
          node._type === 'ImportFrom'
            ? module + '.' + alias.name
            : alias.asname
              ? module
              : module.split('.')[0];
        env.set(name, tagged('reference', reference));
      }
    } else if (node._type === 'Expr') evaluate(node.value);
    else if (node._type === 'Assign') {
      const value = evaluate(node.value);
      for (const target of node.targets) bind(target, value);
    } else if (node._type === 'With') {
      for (const item of node.items) {
        const value = evaluate(item.context_expr);
        if (value?.kind !== 'file') unknown(item.context_expr, 'python_unknown_context_manager');
        if (item.optional_vars) bind(item.optional_vars, value);
      }
      return block(node.body);
    } else if (node._type === 'If') {
      const test = truth(evaluate(node.test), node);
      if (test !== UNKNOWN) return block(test ? node.body : node.orelse);
      const result = fork(
        node,
        () => block(node.body),
        () => block(node.orelse),
      );
      if (result === UNKNOWN) return null;
      if (!result.yes && !result.no) return null;
      if (result.yes?.kind === result.no?.kind)
        return {
          kind: result.yes.kind,
          value: equal(result.yes.value, result.no.value) ? result.yes.value : UNKNOWN,
        };
      unknown(node, 'python_divergent_control_flow');
      return null;
    } else if (node._type === 'While') {
      for (let pass = 0; pass < 2; pass++) {
        const condition = truth(evaluate(node.test), node);
        if (condition === false) break;
        const result = fork(
          node,
          () => block(node.body),
          () => null,
        );
        if (result === UNKNOWN || (result.yes && !['break', 'continue'].includes(result.yes.kind)))
          unknown(node, 'python_loop_control');
      }
      return block(node.orelse);
    } else if (node._type === 'For') {
      const items = evaluate(node.iter);
      if (items?.kind === 'data' && items.value === 'strings') {
        // Merge zero and repeated iterations. Values that vary become unknown.
        for (let pass = 0; pass < 2; pass++) {
          const result = fork(
            node,
            () => {
              bind(node.target, tagged('data', 'str'));
              return block(node.body);
            },
            () => null,
          );
          if (
            result === UNKNOWN ||
            (result.yes && !['break', 'continue'].includes(result.yes.kind))
          )
            unknown(node, 'python_loop_control');
        }
        return block(node.orelse);
      }
      if (items?.kind !== 'sequence' || items.value.length > 32) {
        unknown(node, 'python_dynamic_loop');
        return;
      }
      let broke = false;
      for (const value of items.value) {
        bind(node.target, value);
        const flow = block(node.body);
        if (flow?.kind === 'break') {
          broke = true;
          break;
        }
        if (flow && flow.kind !== 'continue') return flow;
      }
      if (!broke) return block(node.orelse);
    } else if (node._type === 'Break' || node._type === 'Continue')
      return { kind: node._type.toLowerCase() };
    else if (node._type === 'Return')
      return { kind: 'return', value: node.value ? evaluate(node.value) : null };
    else if (node._type === 'Assert') {
      const test = truth(evaluate(node.test), node);
      if (test !== true && node.msg) evaluate(node.msg);
      if (test === false) return { kind: 'stop' };
    } else if (node._type === 'FunctionDef') {
      if (
        callDepth ||
        node.decorator_list.length ||
        node.returns ||
        node.type_params?.length ||
        [
          ...node.args.posonlyargs,
          ...node.args.args,
          ...node.args.kwonlyargs,
          node.args.vararg,
          node.args.kwarg,
        ].some((x) => x?.annotation)
      ) {
        unknown(node, 'python_function_definition');
        env.set(node.name, UNKNOWN);
        return;
      }
      const locals = new Set();
      const scan = (n) => {
        if (!n || typeof n !== 'object') return;
        if (n._type === 'Name' && n.ctx?._type === 'Store') locals.add(n.id);
        if (n._type === 'Import' || n._type === 'ImportFrom')
          for (const a of n.names)
            locals.add(a.asname ?? (n._type === 'Import' ? a.name.split('.')[0] : a.name));
        for (const v of Object.values(n)) if (typeof v === 'object') scan(v);
      };
      scan(node.body);
      env.set(
        node.name,
        tagged('function', {
          node,
          locals,
          defaults: node.args.defaults.map(evaluate),
          kwdefaults: node.args.kw_defaults.map((x) => (x ? evaluate(x) : UNKNOWN)),
        }),
      );
    } else if (node._type !== 'Pass') unknown(node, 'python_statement:' + node._type);
  };
  block(tree.body);
  return { version: 1, semanticComplete: !unresolved.length, effects, unresolved };
}
