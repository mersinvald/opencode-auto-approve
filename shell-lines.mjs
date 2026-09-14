import path from 'node:path';
import { literal } from './shell-words.mjs';

// Derive a small filename stream. The caller validates every command separately.
export async function manifestLines(stmt, { vars, cwd, locale, directory }, input) {
  const bounded = (lines) => {
    if (
      !Array.isArray(lines) ||
      lines.length > 32 ||
      lines.some((s) => typeof s !== 'string' || !s || s.length > 4096 || /[^\x21-\x7e]/.test(s))
    )
      return undefined;
    return lines;
  };
  const options = { vars, cwd, locale, directory };
  if (!stmt || stmt.Background || stmt.Negated || stmt.Coprocess || stmt.Disown) return;
  if ((stmt.Redirs ?? []).some((r) => r.Op !== '>' || r.N)) return;
  const cmd = stmt.Cmd;
  if (cmd?.Type === 'Block') {
    if (input !== undefined) return;
    const output = [];
    let unordered = false;
    for (const child of cmd.Stmts ?? []) {
      if (child.Redirs?.length) return;
      const lines = await manifestLines(child, options);
      if (!lines) return;
      unordered ||= !!lines.unordered;
      output.push(...lines);
      if (output.length > 32) return;
    }
    if (unordered) Object.defineProperty(output, 'unordered', { value: true });
    return bounded(output);
  }
  if (cmd?.Type === 'BinaryCmd' && cmd.Op === '|') {
    if (stmt.Redirs?.length || cmd.X.Redirs?.length) return;
    const left = await manifestLines(cmd.X, options, input);
    if (!left) return;
    return manifestLines(cmd.Y, options, left);
  }
  if (cmd?.Type !== 'CallExpr' || cmd.Assigns?.length) return;
  let argv;
  try {
    argv = cmd.Args.map((w) => literal(w, vars));
  } catch {
    return;
  }
  const [name, ...args] = argv;
  if (
    name === 'printf' &&
    input === undefined &&
    args.length > 1 &&
    ['%s\\n', '%s\n'].includes(args[0])
  )
    return bounded(args.slice(1));
  if (
    name === 'sort' &&
    input &&
    ['C', 'POSIX', 'C.UTF-8', 'C.utf8'].includes(locale) &&
    (args.length === 0 || (args.length === 1 && args[0] === '-u'))
  )
    return bounded((args[0] === '-u' ? [...new Set(input)] : [...input]).sort());
  if (name === 'sed' && input && args.length === 1) {
    const m = /^s([#|])\^([A-Za-z0-9_./:-]+)\1\1$/.exec(args[0]);
    if (m) {
      const output = bounded(input.map((line) => line.replace(new RegExp('^' + m[2]), '')));
      if (output && input.unordered) Object.defineProperty(output, 'unordered', { value: true });
      return output;
    }
  }
  if (
    name === 'find' &&
    input === undefined &&
    args.length === 7 &&
    args[1] === '-maxdepth' &&
    args[2] === '1' &&
    args[3] === '-type' &&
    args[4] === 'f' &&
    args[5] === '-name' &&
    /^[A-Za-z0-9_.*?-]{1,128}$/.test(args[6]) &&
    !args[6].includes('**')
  ) {
    const root = path.resolve(cwd, args[0]);
    if (root !== args[0]) return;
    const entries = await directory(root);
    const regex = new RegExp(
      '^' +
        [...args[6]]
          .map((c) =>
            c === '*' ? '.*' : c === '?' ? '.' : c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
          )
          .join('') +
        '$',
    );
    // Find order is not portable. Mark it until a C-locale sort establishes order.
    const lines = bounded(
      entries.filter((e) => e.file && regex.test(e.name)).map((e) => path.join(args[0], e.name)),
    );
    if (lines) Object.defineProperty(lines, 'unordered', { value: true });
    return lines;
  }
}
