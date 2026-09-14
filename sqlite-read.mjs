// A small SQL recognizer, not a general SQL parser. Unknown statements return
// to model review. SQLite safe mode also blocks effects hidden in database views.
export function sqliteRead(args) {
  const flags = new Set();
  let i = 0;
  while (args[i]?.startsWith('-')) {
    const flag = args[i++].replace(/^--/, '-');
    if (flag === '-init') {
      if (args[i++] !== '/dev/null' || flags.has(flag)) throw Error('sqlite_startup');
    } else if (
      !['-safe', '-readonly', '-batch', '-json', '-header', '-noheader', '-nofollow'].includes(
        flag,
      ) ||
      flags.has(flag)
    )
      throw Error('sqlite_flags');
    flags.add(flag);
  }
  if (!['-safe', '-readonly', '-init'].every((f) => flags.has(f)))
    throw Error('sqlite_safety_flags');
  const [database, sql] = args.slice(i);
  if (
    args.length - i !== 2 ||
    !database ||
    /[:\0\r\n]/.test(database) ||
    typeof sql !== 'string' ||
    sql.length > 8192
  )
    throw Error('sqlite_arguments');
  if (/^\.(?:tables|schema)(?: +[A-Za-z_][A-Za-z0-9_]{0,127})? *$/.test(sql))
    return { database, kind: sql.trim().split(' ')[0] };
  const ident = '[A-Za-z_][A-Za-z0-9_]{0,127}',
    value = "(?:'(?:[^'\\r\\n]|'')*'|[+-]?[0-9]+(?:\\.[0-9]+)?|NULL|TRUE|FALSE)";
  const columns = `(?:\\*|${ident}(?:\\s*,\\s*${ident})*)`;
  const condition = `${ident}\\s*(?:=|!=|<>|<=|>=|<|>)\\s*${value}`;
  const expression = new RegExp(
    `^\\s*SELECT\\s+${columns}\\s+FROM\\s+${ident}(?:\\s+WHERE\\s+${condition}(?:\\s+AND\\s+${condition})*)?(?:\\s+LIMIT\\s+[0-9]{1,6})?\\s*;?\\s*$`,
    'i',
  );
  if (!expression.test(sql)) throw Error('sqlite_statement');
  return { database, kind: 'select' };
}
