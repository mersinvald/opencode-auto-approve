import test from 'node:test';
import assert from 'node:assert/strict';
import { sqliteRead } from './sqlite-read.mjs';
import { mkdtemp, writeFile, readFile, access } from 'node:fs/promises';
import { execFileSync, spawnSync } from 'node:child_process';
const prefix = ['-safe', '-readonly', '-init', '/dev/null', '/fixture/data.db'];
test('SQLite inspection accepts only explicit safe read-only startup and bounded statements', () => {
  for (const sql of [
    '.tables',
    '.schema session_message',
    "SELECT data FROM session_message WHERE id='msg_a' AND session_id='ses_a';",
    'SELECT id, data FROM messages LIMIT 10',
    "SELECT data FROM t WHERE data='a''b; .shell nope'",
  ])
    assert.equal(sqliteRead([...prefix, sql]).database, '/fixture/data.db');
  for (const sql of [
    '.shell echo unsafe',
    '.tables\n.shell echo unsafe',
    "SELECT load_extension('x')",
    'SELECT * FROM t; DELETE FROM t',
    'SELECT * FROM t UNION SELECT * FROM x',
    'ATTACH x AS y',
    'PRAGMA writable_schema=1',
    "SELECT writefile('x',data) FROM t",
    'SELECT * FROM (SELECT * FROM t)',
    'SELECT * FROM t -- comment',
  ])
    assert.throws(() => sqliteRead([...prefix, sql]), sql);
  for (const args of [
    ['-readonly', '/fixture/data.db', '.tables'],
    ['-safe', '-readonly', '-init', '/tmp/script', '/fixture/data.db', '.tables'],
    ['-safe', '-readonly', '-init', '/dev/null', '-nonce', 'x', '/fixture/data.db', '.tables'],
    [...prefix, '.tables', '.shell echo x'],
    ['-safe', '-readonly', '-init', '/dev/null', 'file:other.db?mode=ro', '.tables'],
  ])
    assert.throws(() => sqliteRead(args));
});
test('native SQLite safe mode blocks hidden view effects and skips user startup commands', async () => {
  const root = await mkdtemp(
      (await import('node:fs')).realpathSync((await import('node:os')).tmpdir()) +
        '/opencode-sqlite-safe-',
    ),
    database = root + '/fixture.db',
    marker = root + '/marker';
  execFileSync('/usr/bin/sqlite3', [
    '-init',
    '/dev/null',
    database,
    `CREATE TABLE messages(id TEXT,data TEXT); INSERT INTO messages VALUES('m','{"ok":true}'); CREATE VIEW dangerous AS SELECT writefile('${marker}','bad') AS payload;`,
  ]);
  await writeFile(root + '/.sqliterc', `.shell touch '${marker}'\n`);
  const before = await readFile(database),
    env = { PATH: '/usr/bin:/bin', HOME: root };
  const args = ['-safe', '-readonly', '-init', '/dev/null', database];
  assert.match(
    execFileSync('/usr/bin/sqlite3', [...args, 'SELECT data FROM messages;'], {
      env,
      encoding: 'utf8',
    }),
    /ok/,
  );
  const result = spawnSync('/usr/bin/sqlite3', [...args, 'SELECT payload FROM dangerous;'], {
    env,
    encoding: 'utf8',
  });
  assert.notEqual(result.status, 0);
  await assert.rejects(access(marker));
  assert.deepEqual(await readFile(database), before);
});
