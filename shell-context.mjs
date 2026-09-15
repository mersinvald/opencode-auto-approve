// Lexical context only. This never executes, expands, or approves shell input.
export function requestSourceText(request) {
  // Runtime supplies bounded helper snapshots separately from tool arguments.
  // Source mentions guide review categories and candidate targets, never approval.
  return [
    request.tool?.input?.command ?? '',
    ...(request.scripts ?? []).map((s) => s.text ?? ''),
  ].join('\n');
}

export function shellTokens(command) {
  const tokens = [];
  let word = '',
    started = false,
    quote = null;
  const flush = () => {
    if (started) tokens.push({ text: word });
    word = '';
    started = false;
  };
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
        continue;
      }
      if (ch === '\\' && quote === '"' && /["\\$`\n]/.test(command[i + 1] ?? '')) {
        word += command[++i];
        continue;
      }
      word += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      started = true;
      continue;
    }
    if (ch === '\\') {
      started = true;
      word += command[++i] ?? '';
      continue;
    }
    if (ch === '#' && !started) {
      while (i < command.length && command[i] !== '\n') i++;
    }
    if (i >= command.length) break;
    const current = command[i];
    if (/\s/.test(current)) {
      flush();
      if (current === '\n') tokens.push({ op: '\n' });
      continue;
    }
    if (/[;&|<>(){}]/.test(current)) {
      flush();
      let op = current;
      if (command[i + 1] === current && /[;&|<>]/.test(current)) op += command[++i];
      tokens.push({ op });
      continue;
    }
    started = true;
    word += current;
  }
  flush();
  return tokens;
}

export function commandSegments(command) {
  const result = [];
  let segment = [],
    heredocs = [];
  const tokens = shellTokens(command);
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.op === '<<' && tokens[i + 1]?.text)
      heredocs.push(tokens[i + 1].text.replace(/^-/, ''));
    if (token.op && /^(?:;|;;|&&|\|\||\||&|\n|[(){}])$/.test(token.op)) {
      if (segment.length) result.push(segment);
      segment = [];
      if (token.op === '\n' && heredocs.length) {
        // Bodies are model evidence, not top-level commands or helper paths.
        for (const delimiter of heredocs) {
          while (++i < tokens.length) {
            if (
              tokens[i].text === delimiter &&
              tokens[i - 1]?.op === '\n' &&
              (tokens[i + 1]?.op === '\n' || i + 1 === tokens.length)
            )
              break;
          }
        }
        heredocs = [];
      }
    } else segment.push(token);
  }
  if (segment.length) result.push(segment);
  return result;
}

export function isolatedPythonInvocations(command) {
  const result = [];
  let lookupSafe = !/[$`]/.test(command);
  for (const [segmentIndex, segment] of commandSegments(command).entries()) {
    let start = 0;
    while (/^[A-Za-z_][A-Za-z_0-9]*=/.test(segment[start]?.text ?? '')) start++;
    const interpreter = segment[start]?.text;
    let args = start + 1;
    while (/^-[ISB]+$/.test(segment[args]?.text ?? '')) args++;
    if (
      /^(?:[^\n]*\/)?python(?:3(?:\.\d+)?)?$/.test(interpreter ?? '') &&
      ['I', 'S', 'B'].every((flag) =>
        segment.slice(start + 1, args).some((token) => token.text?.includes(flag)),
      ) &&
      segment[args]?.text
    ) {
      result.push({
        interpreter,
        helper: segment[args].text,
        segmentIndex,
        lookupSafe: lookupSafe && start === 0,
      });
    }
    // A preceding cd cannot change an absolute PATH search. Other commands and
    // assignments may change resolution, so their following invocations need review.
    lookupSafe &&=
      start === 0 && interpreter === 'cd' && segment.length === 2 && !!segment[1]?.text;
  }
  return result;
}

export function helperReferences(command, { dataInvocations = [] } = {}) {
  const compound = /[\n\r`$;&|<>]/.test(command);
  const references = [];
  for (const [segmentIndex, segment] of commandSegments(command).entries()) {
    let start = 0;
    while (/^[A-Za-z_][A-Za-z_0-9]*=/.test(segment[start]?.text ?? '')) start++;
    let args = start + 1;
    while (/^-[ISB]+$/.test(segment[args]?.text ?? '')) args++;
    const isolated = ['I', 'S', 'B'].every((flag) =>
      segment.slice(start + 1, args).some((token) => token.text?.includes(flag)),
    );
    const dataArguments =
      isolated &&
      dataInvocations.some(
        (item) =>
          item.interpreter === segment[start]?.text &&
          item.helper === segment[args]?.text &&
          (item.segmentIndex === undefined || item.segmentIndex === segmentIndex),
      );
    const pytest =
      /^(?:[^\n]*\/)?python(?:3(?:\.\d+)?)?$/.test(segment[start]?.text ?? '') &&
      segment[args]?.text === '-m' &&
      segment[args + 1]?.text === 'pytest';
    for (const [index, token] of segment.entries()) {
      if (token.text === undefined) continue;
      // Pytest selectors name test inputs, not standalone helper executables.
      // The shell adapter expands them into tests.run grants. This skip grants
      // no authority; unsupported runners or options still need model review.
      if (pytest && index > args + 1) continue;
      // Only a verified interpreter and lint helper can classify these as data.
      if (dataArguments && index > args) continue;
      // An output filename is not an existing helper input.
      if (['>', '>>'].includes(segment[index - 1]?.op)) continue;
      const name = token.text.replace(/^[A-Za-z_][A-Za-z_0-9]*=/, '');
      if (!/\.(?:py|sh|bash|js|mjs|cjs|ts)$/.test(name) || /[$`\n\r]/.test(name)) continue;
      // A compound command may change cwd. Only absolute references are reliable candidates.
      if (compound && !name.startsWith('/')) continue;
      references.push(name);
    }
  }
  return [...new Set(references)];
}

// Only a literal, quoted heredoc with a simple cat redirect can supply future
// source. The complete command still goes to the classifier for action review.
export function inlineHelperSources(command) {
  const lines = command.split('\n'),
    sources = [];
  for (let i = 0; i < lines.length; i++) {
    const match =
      /^\s*(?:cat|\/bin\/cat)\s+>\s+('[^']+'|"[^"]+"|[^\s<>;&|]+)\s+<<\s*(['"])([A-Za-z_][A-Za-z0-9_]*)\2\s*$/.exec(
        lines[i],
      );
    if (!match) continue;
    const reference = match[1].replace(/^(['"])(.*)\1$/, '$2');
    if (!reference.startsWith('/') || /[$`\\\r\n]/.test(reference)) continue;
    let end = i + 1;
    while (end < lines.length && lines[end] !== match[3]) end++;
    if (end === lines.length) continue;
    sources.push({
      reference,
      text: lines.slice(i + 1, end).join('\n') + '\n',
      statementLine: i + 1,
      startLine: i + 2,
      endLine: end,
    });
    i = end;
  }
  return sources;
}
