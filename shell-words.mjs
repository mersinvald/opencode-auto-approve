import path from 'node:path';
import { readdir, lstat } from 'node:fs/promises';

const fail = (reason) => {
  throw Error(reason);
};
function characters(word, vars, quoted = false) {
  const result = [];
  for (const part of word?.Parts ?? fail('unsupported_word')) {
    if (part.Type === 'Lit') {
      const value = part.Value;
      for (let i = 0; i < value.length; i++) {
        let c = value[i],
          active = !quoted;
        if (/[\0-\x1f\x7f]/.test(c)) fail('word_control');
        if (c === '\\') {
          const next = value[++i];
          if (next === undefined) fail('word_escape');
          if (next === '\n') continue;
          if (quoted && !['$', '`', '"', '\\'].includes(next))
            result.push({ c: '\\', active: false });
          c = next;
          active = false;
        }
        if (active && /[~{}[\]]/.test(c)) fail('dynamic_expansion');
        result.push({ c, active });
      }
    } else if (part.Type === 'SglQuoted' && !part.Dollar) {
      for (const c of part.Value) result.push({ c, active: false });
    } else if (part.Type === 'DblQuoted' && !part.Dollar) {
      result.push(...characters(part, vars, true));
    } else if (
      part.Type === 'ParamExp' &&
      Object.keys(part).every((k) =>
        ['Type', 'Pos', 'End', 'Dollar', 'Short', 'Param', 'Rbrace'].includes(k),
      ) &&
      Object.hasOwn(vars, part.Param?.Value) &&
      (quoted || /^[a-zA-Z0-9_./:-]+$/.test(vars[part.Param.Value]))
    ) {
      for (const c of vars[part.Param.Value]) result.push({ c, active: false });
    } else fail('dynamic_expansion');
  }
  return result;
}
export function literal(word, vars) {
  const chars = characters(word, vars);
  if (chars.some((x) => x.active && '*?'.includes(x.c))) fail('dynamic_expansion');
  return chars.map((x) => x.c).join('');
}
export function arrayExpansion(word, arrays) {
  const quoted = word?.Parts?.length === 1 && word.Parts[0];
  const param =
    quoted?.Type === 'DblQuoted' && !quoted.Dollar && quoted.Parts?.length === 1 && quoted.Parts[0];
  if (param?.Type !== 'ParamExp' || !Object.hasOwn(arrays, param.Param?.Value)) return null;
  if (
    !Object.keys(param).every((k) =>
      ['Type', 'Pos', 'End', 'Dollar', 'Param', 'Rbrace', 'Index'].includes(k),
    ) ||
    param.Index?.Type !== 'Word' ||
    param.Index.Parts?.length !== 1 ||
    param.Index.Parts[0].Type !== 'Lit' ||
    param.Index.Parts[0].Value !== '@'
  )
    fail('array_expansion');
  return [...arrays[param.Param.Value]];
}
const escaped = (c) => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Expand only bounded filename wildcards. Never evaluate shell code.
export async function expandWord(word, vars, cwd, readDirectory) {
  const chars = characters(word, vars),
    value = chars.map((x) => x.c).join('');
  if (!chars.some((x) => x.active && '*?'.includes(x.c))) return [value];
  const parts = [[]];
  for (const x of chars) {
    if (x.c === '/') parts.push([]);
    else parts.at(-1).push(x);
  }
  if (
    parts.some(
      (p) =>
        p.map((x) => x.c).join('') === '..' ||
        p.some((x, i) => x.active && x.c === '*' && p[i + 1]?.active && p[i + 1].c === '*'),
    )
  )
    fail('recursive_glob');
  let current = [value.startsWith('/') ? '/' : cwd],
    visited = 0;
  for (const part of parts.filter((p) => p.length && p.map((x) => x.c).join('') !== '.')) {
    const pattern = part.some((x) => x.active && '*?'.includes(x.c));
    if (!pattern) {
      current = current.map((p) => path.join(p, part.map((x) => x.c).join('')));
      continue;
    }
    if (part.filter((x) => x.active && '*?'.includes(x.c)).length > 8) fail('glob_limit');
    const expression = new RegExp(
      '^' +
        part
          .map((x) =>
            x.active && x.c === '*' ? '.*' : x.active && x.c === '?' ? '.' : escaped(x.c),
          )
          .join('') +
        '$',
    );
    const next = [];
    for (const directory of current) {
      if (++visited > 128) fail('glob_limit');
      const stat = await lstat(directory).catch((e) => {
        if (e.code !== 'ENOENT') throw e;
      });
      if (!stat) continue;
      if (!stat.isDirectory() || stat.isSymbolicLink()) fail('glob_directory');
      await readDirectory(directory);
      const entries = await readdir(directory, { withFileTypes: true });
      if (entries.length > 4096) fail('glob_limit');
      for (const entry of entries) {
        if (entry.name.startsWith('.') && part[0]?.c !== '.') continue;
        if (!expression.test(entry.name)) continue;
        next.push(path.join(directory, entry.name));
        if (next.length > 128) fail('glob_limit');
      }
    }
    current = next;
  }
  const existing = [];
  for (const file of current) {
    if (
      await lstat(file).catch((e) => {
        if (e.code !== 'ENOENT') throw e;
      })
    )
      existing.push(file);
  }
  if (!existing.length) fail('glob_no_matches');
  return existing
    .sort()
    .map((p) =>
      value.startsWith('/') ? p : (value.startsWith('./') ? './' : '') + path.relative(cwd, p),
    );
}
