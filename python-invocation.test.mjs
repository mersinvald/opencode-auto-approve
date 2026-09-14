import test from 'node:test';
import assert from 'node:assert/strict';
import { pythonInvocation } from './python-invocation.mjs';

const parse = (args, stdin) => pythonInvocation(args, { cwd: '/repo', stdin });

test('Python argv separates source, flags, script arguments and known stdin', () => {
  const inline = parse(['python3', '-IBc', 'print("x")', '-S']);
  assert.equal(inline.complete, true);
  assert.deepEqual(inline.source, { kind: 'inline', text: 'print("x")' });
  assert.deepEqual(inline.argv, ['-c', '-S']);
  assert.equal(inline.startup.required, true);
  assert.equal(parse(['python3', '-cprint(1)']).source.text, 'print(1)');
  const stdin = parse(['python3', '-', 'arg'], 'print(1)');
  assert.deepEqual(stdin.argv, ['-', 'arg']);
  assert.equal(stdin.source.text, 'print(1)');
  const file = parse(['/venv/bin/python', '-I', '-S', '--', '-script.py', '-c']);
  assert.equal(file.source.path, '/repo/-script.py');
  assert.deepEqual(file.argv, ['-script.py', '-c']);
  assert.equal(file.executable, '/venv/bin/python');
});

test('Python startup waiver requires both isolation and no-site flags', () => {
  for (const flags of [[], ['-S'], ['-I'], ['-E', '-S'], ['-P', '-s', '-S']]) {
    const result = parse(['python3', ...flags, '-c', 'pass']);
    assert.equal(result.complete, true);
    assert.equal(result.startup.required, true, JSON.stringify(flags));
  }
  for (const flags of [['-I', '-S'], ['-IS'], ['-SIB']]) {
    const result = parse(['python3', ...flags, '-c', 'pass']);
    assert.equal(result.startup.required, false);
    assert.equal(result.isolation.ignoreEnvironment, true);
  }
});

test('unsupported Python launch forms remain incomplete rather than guessing source', () => {
  for (const args of [
    ['python3'],
    ['python3', '-'],
    ['python3', '--'],
    ['python3', '-c'],
    ['python3', '-m', 'unknown'],
    ['python3', '-X', 'presite=evil', 'f.py'],
    ['python3', '-i', 'f.py'],
    ['python3', '--check-hash-based-pycs=never', 'f.py'],
    ['python3', 'link/../f.py'],
    ['pypy', '-c', 'pass'],
    ['python3', '-c', 'a\0b'],
  ])
    assert.equal(parse(args).complete, false, JSON.stringify(args));
});
