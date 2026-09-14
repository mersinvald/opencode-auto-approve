import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, realpath } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sha256 } from './shell-host.mjs';
import { parsePythonSource } from './python-host.mjs';

const interpreterPath = execFileSync(
  'python3',
  ['-I', '-S', '-B', '-c', 'import sys; print(sys.executable)'],
  { encoding: 'utf8' },
).trim();
const driver = fileURLToPath(new URL('./python-parser/parse.py', import.meta.url));
const parser = {
  path: driver,
  sha256: sha256(await readFile(driver)),
  interpreter: {
    path: interpreterPath,
    realpath: await realpath(interpreterPath),
    sha256: sha256(await readFile(interpreterPath)),
  },
};

test('isolated Python AST host parses effects as syntax without executing input', async () => {
  const result = await parsePythonSource(
    "import os\nopen('/NEVER_EXECUTE_APPROVAL_SOURCE', 'w')",
    parser,
  );
  assert.equal(result.status, 'parsed');
  assert.equal(result.ast.body[0]._type, 'Import');
  assert.equal(result.ast.body[1].value.func.id, 'open');
  assert.equal(result.ast.body[1].lineno, 2);
  const bad = await parsePythonSource('x = (', parser);
  assert.equal(bad.reason, 'python_syntax');
});

test('parser integrity, bounds, and cancellation fail closed', async () => {
  await assert.rejects(
    parsePythonSource('pass', { ...parser, sha256: '0'.repeat(64) }),
    /python_parser_changed/,
  );
  await assert.rejects(
    parsePythonSource('pass', {
      ...parser,
      interpreter: { ...parser.interpreter, sha256: '0'.repeat(64) },
    }),
    /python_parser_changed/,
  );
  await assert.rejects(parsePythonSource('x'.repeat(65537), parser), /python_source_limit/);
  const abort = new AbortController();
  abort.abort();
  await assert.rejects(parsePythonSource('pass', parser, abort.signal), { name: 'AbortError' });
  const directory = await mkdtemp(realpathSync(tmpdir()) + '/python-parser-host-');
  const slow = directory + '/slow.py';
  await writeFile(slow, 'import time\ntime.sleep(10)\n');
  const started = Date.now();
  await assert.rejects(
    parsePythonSource('pass', { ...parser, path: slow, sha256: sha256(await readFile(slow)) }),
    /python_parse_timeout/,
  );
  assert.ok(Date.now() - started < 4000);
});
