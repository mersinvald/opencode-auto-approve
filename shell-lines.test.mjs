import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { manifestLines } from './shell-lines.mjs';
const parser = fileURLToPath(new URL('./bin/shell-parser', import.meta.url));
const inspect = async (command) =>
  manifestLines(JSON.parse(execFileSync(parser, ['bash'], { input: command })).Stmts[0], {
    vars: {},
    cwd: '/repo',
    locale: 'C',
    directory: async () => [
      { name: 'z.json', file: true },
      { name: 'a.json', file: true },
      { name: 'link.json', file: false },
    ],
  });
test('manifest provenance derives bounded find, literal prefix removal and C-locale sort', async () => {
  const r = await inspect(
    '{ find /repo -maxdepth 1 -type f -name "*.json"; printf "%s\\n" /repo/x; } | sed "s#^/repo/##" | sort -u > files',
  );
  assert.deepEqual(r, ['a.json', 'x', 'z.json']);
  assert.ok(!r.unordered);
});
test('manifest proof rejects unsupported output and preserves unordered directory provenance', async () => {
  for (const cmd of [
    "printf '%s\\n' > files",
    'echo /repo/x > files',
    'printf "%s\\n" "two words"',
    'printf "%s\\n" x | sed "s/x/y/e"',
  ])
    assert.equal(await inspect(cmd), undefined, cmd);
  assert.equal((await inspect('find /repo -maxdepth 1 -type f -name "*.json"')).unordered, true);
});
