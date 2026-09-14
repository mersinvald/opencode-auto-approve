// Deliberately small data-language grammars. No filter or shell code is executed.
export function safeSed(program, quiet) {
  // Only print with numeric, end-of-file, or slash-regex addresses. No sed
  // commands, e/w flags, newline separators, or alternate delimiters.
  const address = String.raw`(?:\d{1,6}|\$|/(?:[^/\\\r\n]|\\[^\r\n])*/)`;
  if (quiet && new RegExp(`^${address}(,${address})?p$`).test(program)) return true;
  // One substitution, slash delimiter, no e/w flags or additional commands.
  // Escaped slash is handled as data; a literal newline is never a separator.
  return /^s\/(?:[^/\\\r\n]|\\[^\r\n])*\/(?:[^/\\\r\n]|\\[^\r\n])*\/[gp]*$/.test(program);
}

export function safeMetadataFilter(source, variables) {
  if (typeof source !== 'string' || source.length > 4096) return false;
  const tokens = [];
  let pos = 0;
  const token =
    /\s*("(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?|[A-Za-z_][A-Za-z0-9_]*|[.$\[\]{}():,+|=])/y;
  while (pos < source.length) {
    if (/^\s*$/.test(source.slice(pos))) break;
    token.lastIndex = pos;
    const m = token.exec(source);
    if (!m || tokens.length >= 512) return false;
    tokens.push(m[1]);
    pos = token.lastIndex;
  }
  let i = 0,
    depth = 0;
  const expect = (x) => {
    if (tokens[i++] !== x) throw Error('syntax');
  };
  const name = () => {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(tokens[i] ?? '')) throw Error('name');
    return tokens[i++];
  };
  const suffix = () => {
    let found = false;
    while (tokens[i] === '.' || tokens[i] === '[') {
      found = true;
      if (tokens[i++] === '.') name();
      else {
        if (!/^\d{1,6}$/.test(tokens[i++] ?? '')) throw Error('index');
        expect(']');
      }
    }
    return found;
  };
  const value = () => {
    if (++depth > 16) throw Error('depth');
    const t = tokens[i++];
    let kind = 'json';
    if (t === '{') {
      kind = 'json-object';
      if (tokens[i] !== '}')
        do {
          if (tokens[i]?.startsWith('"')) JSON.parse(tokens[i++]);
          else name();
          expect(':');
          expression();
          if (tokens[i] !== ',') break;
          i++;
        } while (true);
      expect('}');
    } else if (t === '[') {
      if (tokens[i] !== ']')
        do {
          expression();
          if (tokens[i] !== ',') break;
          i++;
        } while (true);
      expect(']');
    } else if (t === '(') {
      kind = expression();
      expect(')');
    } else if (t === '$') {
      const variable = name();
      if (!variables.has(variable)) throw Error('variable');
      kind = variables.get(variable);
      if (suffix()) kind = 'json';
    } else if (t === '.') {
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tokens[i] ?? '')) name();
      suffix();
    } else if (t?.startsWith('"')) JSON.parse(t);
    else if (!/^(?:null|true|false|-?\d+(?:\.\d+)?)$/.test(t ?? '')) throw Error('value');
    depth--;
    return kind;
  };
  const expression = () => {
    let kind = value();
    while (tokens[i] === '+') {
      i++;
      const right = value();
      if (right === 'json-object') kind = right;
    }
    return kind;
  };
  try {
    let kind = expression();
    // Constant field assignments only. No modules, functions, update operators,
    // generators, recursive descent, or file loaders enter this grammar.
    while (tokens[i] === '|') {
      i++;
      expect('.');
      name();
      while (tokens[i] === '.') {
        i++;
        name();
      }
      expect('=');
      expression();
      kind = 'json-object';
    }
    return i === tokens.length ? { kind } : false;
  } catch {
    return false;
  }
}

export function gitInspection(operation, args) {
  const a = [...args],
    paths = [];
  const ref = (x) =>
    /^(?:HEAD(?:[~^]\d*)?|[a-f0-9]{7,40})(?:\.\.(?:HEAD|[a-f0-9]{7,40}))?$/.test(x);
  const cut = a.indexOf('--');
  if (cut >= 0) {
    paths.push(...a.splice(cut + 1));
    a.splice(cut);
    if (!paths.length) return null;
  }
  if (operation === 'status') {
    // Git accepts literal status pathspecs without the optional separator.
    for (let i = 0; i < a.length; ) {
      if (!a[i].startsWith('-')) paths.push(a.splice(i, 1)[0]);
      else i++;
    }
  }
  if (operation === 'ls-tree') {
    const first = a.findIndex((x) => !x.startsWith('-'));
    if (first < 0 || !ref(a[first])) return null;
    paths.unshift(...a.splice(first + 1));
  }
  if (paths.length && !['status', 'show', 'diff', 'log', 'ls-tree'].includes(operation))
    return null;
  const valid =
    (operation === 'status' &&
      a.every((x) =>
        [
          '--short',
          '--porcelain',
          '--porcelain=v1',
          '--porcelain=v2',
          '--untracked-files=all',
          '--untracked-files=normal',
        ].includes(x),
      )) ||
    (operation === 'rev-parse' &&
      a.length &&
      a.every(
        (x) =>
          ref(x) ||
          [
            '--show-toplevel',
            '--git-dir',
            '--git-common-dir',
            '--is-inside-work-tree',
            '--verify',
          ].includes(x),
      )) ||
    (operation === 'log' &&
      a.every(
        (x) => ref(x) || /^-[0-9]{1,3}$/.test(x) || ['--oneline', '--format=%H %s'].includes(x),
      )) ||
    (operation === 'diff' &&
      a.length &&
      a.every(
        (x) =>
          ref(x) ||
          [
            '--check',
            '--stat',
            '--name-only',
            '--name-status',
            '--cached',
            '--no-ext-diff',
            '--no-textconv',
          ].includes(x),
      )) ||
    (operation === 'show' &&
      a.includes('--stat') &&
      a.every(
        (x) => ref(x) || ['--stat', '--oneline', '--no-ext-diff', '--no-textconv'].includes(x),
      )) ||
    (operation === 'ls-tree' &&
      a.some(ref) &&
      a.every((x) => ref(x) || ['--name-only', '--name-status', '-r', '-d', '-l'].includes(x))) ||
    (operation === 'branch' &&
      (a.join(' ') === '--show-current' ||
        (a.length > 0 &&
          a.every(
            (x) => /^-[arv]+$/.test(x) || ['--all', '--remotes', '--list', '--verbose'].includes(x),
          )))) ||
    (operation === 'worktree' && a.join(' ') === 'list --porcelain');
  return valid && paths.length <= 32 ? { paths } : null;
}
