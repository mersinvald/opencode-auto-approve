// Parse a bounded sed grammar into file effects. Never execute the program.
const fail = (reason = 'sed_program') => {
  throw Error(reason);
};
const delimiter = (c) => typeof c === 'string' && /^[\/|#@%:!~,_;=+?\-]$/.test(c);

export function sedProgram(source) {
  if (typeof source !== 'string' || source.length > 32768 || /[\0\r]/.test(source)) fail();
  const reads = [],
    writes = [];
  let i = 0,
    blocks = 0,
    count = 0;
  const spaces = () => {
    while (source[i] === ' ' || source[i] === '\t') i++;
  };
  const delimited = (d, regex = false) => {
    while (i < source.length) {
      const c = source[i++];
      if (c === '\n') fail();
      if (c === '\\') {
        if (i === source.length || source[i] === '\n') fail();
        i++;
        continue;
      }
      if (c === d) return;
      if (regex && c === '[') {
        if (source[i] === '^') i++;
        if (source[i] === ']') i++;
        while (i < source.length && source[i] !== ']') {
          if (source[i] === d || source[i] === '\n') fail('sed_regex_delimiter');
          if (source[i] === '\\') {
            if (!source[i + 1] || source[i + 1] === '\n') fail();
            i += 2;
          } else if (source[i] === '[' && [':', '.', '='].includes(source[i + 1])) {
            const end = source.indexOf(source[i + 1] + ']', i + 2);
            if (end < 0 || source.slice(i, end).includes(d) || source.slice(i, end).includes('\n'))
              fail();
            i = end + 2;
          } else i++;
        }
        if (source[i++] !== ']') fail();
      }
    }
    fail('sed_unterminated_expression');
  };
  const address = (second = false) => {
    spaces();
    const match =
      /^(?:\d+(?:~\d+)?|\$)/.exec(source.slice(i)) ??
      (second ? /^[+~]\d+/.exec(source.slice(i)) : null);
    if (match) {
      i += match[0].length;
      return true;
    }
    if (source[i] === '/' || (source[i] === '\\' && delimiter(source[i + 1]))) {
      if (source[i] === '\\') i++;
      const d = source[i++];
      delimited(d, true);
      while (source[i] === 'I' || source[i] === 'M') i++;
      return true;
    }
    return false;
  };
  const filename = (into) => {
    spaces();
    const start = i;
    while (i < source.length && source[i] !== '\n') i++;
    const value = source.slice(start, i);
    // r/w filenames run to end of line, not to a semicolon. Avoid dialect
    // differences in escaped filenames and trailing whitespace.
    if (!value || /[;{}\\]/.test(value) || /\s$/.test(value)) fail('sed_filename');
    into.push(value);
  };
  const end = () => {
    spaces();
    if (i < source.length && ![';', '\n', '}', '#'].includes(source[i])) fail();
  };
  while (i < source.length) {
    if (++count > 2048) fail('sed_program_limit');
    spaces();
    if (source[i] === ';' || source[i] === '\n') {
      i++;
      continue;
    }
    if (source[i] === '#') {
      while (i < source.length && source[i] !== '\n') i++;
      continue;
    }
    if (i === source.length) break;
    if (source[i] === '}') {
      if (!blocks--) fail();
      i++;
      end();
      continue;
    }
    if (address()) {
      spaces();
      if (source[i] === ',') {
        i++;
        if (!address(true)) fail();
      }
      spaces();
      if (source[i] === '!') {
        i++;
        spaces();
      }
    }
    const command = source[i++];
    if (command === '{') {
      if (++blocks > 32) fail();
      continue;
    }
    if (command === 'e') fail('sed_execution');
    if (command === 's' || command === 'y') {
      const d = source[i++];
      if (!delimiter(d)) fail('sed_delimiter');
      delimited(d, command === 's');
      delimited(d);
      if (command === 's') {
        while (i < source.length) {
          spaces();
          if (source[i] === 'e') fail('sed_execution');
          if (source[i] === 'w') {
            i++;
            filename(writes);
            break;
          }
          const flag = /^(?:[gpIiMm]|\d+)/.exec(source.slice(i));
          if (!flag) break;
          i += flag[0].length;
        }
      }
    } else if (['r', 'R', 'w', 'W'].includes(command)) {
      filename(command.toLowerCase() === 'r' ? reads : writes);
    } else if (['q', 'Q', 'l'].includes(command)) {
      spaces();
      const number = /^\d+/.exec(source.slice(i));
      if (number) i += number[0].length;
    } else if (['b', 't', 'T', ':'].includes(command)) {
      spaces();
      const label = /^[A-Za-z_][A-Za-z0-9_-]*/.exec(source.slice(i));
      if (label) i += label[0].length;
      else if (command === ':') fail();
    } else if (
      !['p', 'P', 'd', 'D', 'h', 'H', 'g', 'G', 'x', 'n', 'N', 'z', '=', 'F'].includes(command)
    ) {
      fail('sed_unsupported_command');
    }
    end();
  }
  if (blocks) fail('sed_unclosed_block');
  return { reads, writes };
}

export function sedInvocation(args, { dialect = 'unknown', piped = false } = {}) {
  if (!Array.isArray(args) || args.some((a) => typeof a !== 'string')) fail('sed_arguments');
  const scripts = [],
    operands = [];
  let ended = false,
    inPlace = false,
    suffix = '';
  const backup = (value) => {
    if (inPlace || typeof value !== 'string' || !/^[A-Za-z0-9._-]{0,64}$/.test(value))
      fail('sed_backup_suffix');
    inPlace = true;
    suffix = value;
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!ended && a === '--') {
      ended = true;
      continue;
    }
    if (!ended && a.startsWith('-') && a !== '-') {
      if (operands.length) fail('sed_option_order');
      if (a === '--expression') {
        scripts.push(args[++i]);
        continue;
      }
      if (a.startsWith('--expression=')) {
        scripts.push(a.slice(13));
        continue;
      }
      if (
        [
          '--quiet',
          '--silent',
          '--regexp-extended',
          '--posix',
          '--sandbox',
          '--separate',
          '--unbuffered',
          '--null-data',
        ].includes(a)
      )
        continue;
      if (a === '--in-place' || a.startsWith('--in-place=')) {
        if (dialect !== 'gnu') fail('sed_dialect');
        backup(a === '--in-place' ? '' : a.slice(11));
        continue;
      }
      if (a.startsWith('--')) fail('sed_flags');
      for (let k = 1; k < a.length; k++) {
        const flag = a[k];
        if ('nErsuz'.includes(flag)) continue;
        if (flag === 'e') {
          scripts.push(a.slice(k + 1) || args[++i]);
          break;
        }
        if (flag === 'i') {
          if (a.length > k + 1) backup(a.slice(k + 1));
          else if (dialect === 'bsd') backup(args[++i]);
          else if (dialect === 'gnu') backup('');
          else fail('sed_dialect');
          break;
        }
        fail(flag === 'f' ? 'sed_script_file' : 'sed_flags');
      }
    } else operands.push(a);
  }
  if (!scripts.length) scripts.push(operands.shift());
  if (scripts.some((s) => typeof s !== 'string')) fail('sed_missing_program');
  const effects = sedProgram(scripts.join('\n'));
  if (inPlace && (!operands.length || operands.includes('-'))) fail('sed_in_place_input');
  if (!operands.length && !piped) fail('unbound_input');
  if (operands.includes('-') && !piped) fail('unbound_input');
  const inputs = operands.filter((a) => a !== '-');
  return { ...effects, inputs, inPlace, suffix };
}
