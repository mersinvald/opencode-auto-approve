import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { pythonEffects } from './python-effects.mjs';
const driver = fileURLToPath(new URL('./python-parser/parse.py', import.meta.url));
const inspect = (source) =>
  pythonEffects(
    JSON.parse(
      execFileSync('python3', ['-I', '-S', '-B', driver], { input: source, encoding: 'utf8' }),
    ).ast,
    { cwd: '/fixture/repo', source: 'helper.py' },
  );
const files = (r) => r.effects.filter((e) => e.kind === 'file').map((e) => [e.operation, e.target]);

test('Python source resolves pathlib and open aliases to file effects with locations', () => {
  const r = inspect(
    "from pathlib import Path as P\nroot=P('src')\ndata=(root/'a.txt').read_text()\nwith open(root/'b.txt','w') as out:\n    out.write(data)\n(root/'old').unlink()\n",
  );
  assert.equal(r.semanticComplete, true, JSON.stringify(r.unresolved));
  assert.deepEqual(files(r), [
    ['files.read', '/fixture/repo/src/a.txt'],
    ['files.write', '/fixture/repo/src/b.txt'],
    ['files.delete', '/fixture/repo/src/old'],
  ]);
  assert.equal(r.effects.find((e) => e.operation === 'files.read').line, 3);
  assert.deepEqual(
    r.effects.filter((e) => e.kind === 'import').map((e) => e.module),
    ['pathlib'],
  );
});
test('read-write modes and os paths retain every file operation', () => {
  const r = inspect(
    "import os as fs\nfs.chdir('sub')\np=fs.path.join(fs.getcwd(),'f')\nwith open(p,'r+') as f:\n    f.write('x')\nfs.remove(p)\n",
  );
  assert.equal(r.semanticComplete, true, JSON.stringify(r.unresolved));
  assert.deepEqual(files(r), [
    ['files.access', '/fixture/repo/sub'],
    ['files.read', '/fixture/repo/sub/f'],
    ['files.write', '/fixture/repo/sub/f'],
    ['files.delete', '/fixture/repo/sub/f'],
  ]);
});
test('subprocess preserves argv, shell boundaries, cwd and environment for the command adapter', () => {
  const r = inspect(
    "import subprocess as sp\nsp.run(['git','status','--short'],cwd='worktree',capture_output=True,text=True)\nsp.run('git status --short',shell=False)\nsp.run('git status | head -5',shell=True,env={'PATH':'/usr/bin:/bin'})\n",
  );
  assert.equal(r.semanticComplete, true, JSON.stringify(r.unresolved));
  const cmds = r.effects.filter((e) => e.kind === 'command');
  assert.deepEqual(cmds[0].argv, ['git', 'status', '--short']);
  assert.equal(cmds[0].cwd, '/fixture/repo/worktree');
  assert.deepEqual(cmds[1].argv, ['git status --short']);
  assert.equal(cmds[1].shell, false);
  assert.equal(cmds[2].command, 'git status | head -5');
  assert.equal(cmds[2].environment.PATH, '/usr/bin:/bin');
});
test('rebinding, computed paths, unknown calls and execution options preserve incompleteness', () => {
  for (const source of [
    "import pathlib\npathlib.Path=unknown\npathlib.Path('f').read_text()",
    "open=unknown\nopen('f','w')",
    "name=open('input').read()\nopen(name,'w')",
    'import jsonschema\njsonschema.validate({}, {})',
    "import subprocess\nsubprocess.run(['git','status'],preexec_fn=unknown)",
    "import subprocess\nsubprocess.run(['echo $1','zero','value'],shell=True)",
  ])
    assert.equal(inspect(source).semanticComplete, false, source);
  const partial = inspect("open('first').read()\nunknown()\nopen('last','w').write('x')");
  assert.equal(partial.semanticComplete, false);
  assert.deepEqual(files(partial), [
    ['files.read', '/fixture/repo/first'],
    ['files.write', '/fixture/repo/last'],
  ]);
});

test('Path objects preserve lexical relativity across Python cwd changes', () => {
  const result = inspect(`from pathlib import Path
import os
p = Path('data') / 'value.txt'
parent = Path('.').parent
absolute = Path('/other') / 'x.txt'
os.chdir('new')
p.read_text()
(parent / 'sibling.txt').write_text('x')
absolute.read_text()
Path('').joinpath('a', '/reset', 'b').read_text()
`);
  assert.equal(result.semanticComplete, true, JSON.stringify(result.unresolved));
  assert.deepEqual(files(result), [
    ['files.access', '/fixture/repo/new'],
    ['files.read', '/fixture/repo/new/data/value.txt'],
    ['files.write', '/fixture/repo/new/sibling.txt'],
    ['files.read', '/other/x.txt'],
    ['files.read', '/reset/b'],
  ]);
});

test('codecs, hidden call options, module properties and dynamic process input need review', () => {
  for (const source of [
    "open('f','r',-1,'evil-codec').read()",
    "open('f',encoding='evil-codec').read()",
    "from pathlib import Path\nPath('f').read_text(errors='evil-handler')",
    "from pathlib import Path\nPath('f').open('r',-1,'evil-codec')",
    "from pathlib import Path\nPath('a/../secret').read_text()",
    "from pathlib import PurePath\nPurePath('f').read_text()",
    'import evil\nevil.attribute',
    "import subprocess\nsubprocess.run(['python3','-'],input=open('source').read())",
    "open('f',__proto__={'opener':unknown})",
  ])
    assert.equal(inspect(source).semanticComplete, false, source);
  assert.equal(inspect("open('f',encoding='utf-8',errors='strict').read()").semanticComplete, true);
});

test('bounded abstract values prevent exponential expansion', () => {
  for (const start of ["x='aaaaaaaa'", "x=['a']"]) {
    const result = inspect(start + '\n' + Array(32).fill('x=x+x').join('\n') + '\nopen(x)');
    assert.equal(result.semanticComplete, false);
    assert.ok(result.unresolved.some((x) => x.reason === 'python_value_limit'));
    assert.ok(result.unresolved.length <= 128);
  }
  const paths = inspect(
    "from pathlib import Path\nx=Path('a')\n" + Array(32).fill('x=x/x').join('\n'),
  );
  assert.equal(paths.semanticComplete, false);
  assert.ok(paths.unresolved.some((x) => x.reason === 'python_value_limit'));
});

test('bounded functions resolve arguments, defaults, globals at call time and returned paths', () => {
  const result = inspect(`from pathlib import Path
root = 'before'
def read(name='x', *, base='data'):
    return (Path(root) / base / name).read_text()
root = 'after'
read('first')
read(name='second',base='other')
def file(name):
    return Path('output') / name
file('third').write_text('ok')
`);
  assert.equal(result.semanticComplete, true, JSON.stringify(result.unresolved));
  assert.deepEqual(files(result), [
    ['files.read', '/fixture/repo/after/data/first'],
    ['files.read', '/fixture/repo/after/other/second'],
    ['files.write', '/fixture/repo/output/third'],
  ]);
});

test('finite loops and both unknown branches preserve all effects', () => {
  const result = inspect(`from pathlib import Path
def clean(name):
    if Path('flag').exists():
        Path(name).unlink()
    else:
        Path(name).write_text('keep')
for name in ['a','b']:
    clean(name)
for n in range(2):
    Path(f'out{n}').write_text('ok')
`);
  assert.equal(result.semanticComplete, true, JSON.stringify(result.unresolved));
  for (const name of ['a', 'b']) {
    assert.ok(files(result).some(([op, p]) => op === 'files.delete' && p.endsWith('/' + name)));
    assert.ok(files(result).some(([op, p]) => op === 'files.write' && p.endsWith('/' + name)));
  }
  assert.ok(files(result).some(([, p]) => p === '/fixture/repo/out1'));
});

test('branch-local globals, scalar conditions and loop control use Python semantics', () => {
  const result = inspect(`from pathlib import Path
root='old'
def read():
    Path(root).read_text()
if Path('flag').exists():
    root='yes'
    read()
else:
    root='no'
    read()
if 1 is True:
    Path('wrong').read_text()
else:
    Path('right').read_text()
for name in ['one','two','three']:
    if name == 'two':
        break
    Path(name).read_text()
`);
  assert.equal(result.semanticComplete, true, JSON.stringify(result.unresolved));
  assert.deepEqual(
    files(result).map(([, p]) => p.split('/').at(-1)),
    ['flag', 'yes', 'no', 'right', 'one'],
  );
});

test('ambiguous paths, closure mutation, recursion and dynamic loops remain incomplete', () => {
  for (const source of [
    "from pathlib import Path\nif Path('flag').exists():\n p='a'\nelse:\n p='b'\nPath(p).read_text()",
    'def a():\n return a()\na()',
    'def a():\n global x\n x=1\na()',
    'for item in unknown:\n open(item)',
    'for n in range(1000000000000):\n open(str(n))',
    "def f():\n if unknown:\n  return 'x'\n open('y')\nf()",
    "def f(x=open('a')):\n return x\nf(unknown=1)",
    '@unknown\ndef f():\n pass',
    'from io import unknown_object\nstr(unknown_object)',
    'from io import unknown_object\nlen(unknown_object)',
    'from io import unknown_object\nprint(unknown_object)',
    'from io import unknown_object\nif unknown_object:\n pass',
  ])
    assert.equal(inspect(source).semanticComplete, false, source);
});

test('finite verification dataflow preserves reads through hashes, comprehensions and slicing', () => {
  const r = inspect(`from pathlib import Path
import hashlib, json
names=sorted(['z','a'])
fps=[hashlib.sha256(Path(name).read_bytes()).hexdigest()[:16] for name in names]
print(' '.join(fps), len(fps))
print(json.loads(Path('result.json').read_text()))
print('a\\nb\\n'.splitlines())
for name in sorted({'x':'a','y':'b'}.values()):
    print(Path(name).read_text())
`);
  assert.equal(r.semanticComplete, true, JSON.stringify(r.unresolved));
  assert.deepEqual(
    files(r).map(([, p]) => p.split('/').at(-1)),
    ['a', 'z', 'result.json', 'a', 'b'],
  );
});

test('verification helpers do not authorize callbacks, arbitrary methods or dynamic paths', () => {
  for (const source of [
    "import json\njson.loads('{}', object_hook=unknown)",
    "sorted(['a'],key=unknown)",
    "from pathlib import Path\nPath('a').read_text().dangerous()",
    "from pathlib import Path\nPath(Path('a').read_text().encode()).write_text('x')",
    'from pathlib import Path\n[Path(x).read_text() for x in unknown]',
    "from pathlib import Path\nlist(Path('a').glob('**/*'))",
    "from pathlib import Path\n[Path(x).read_text() for x in ['a'] if unknown]",
    "from pathlib import Path\n(Path('a').unlink() for x in ['a'])",
  ])
    assert.equal(inspect(source).semanticComplete, false, source);
});

test('unknown loop counts can use a union of invariant effects without evaluating data', () => {
  for (const source of [
    "from pathlib import Path\nfor line in Path('input').read_text().splitlines():\n    Path('out').write_text('ok')",
    "from pathlib import Path\nwhile Path('flag').exists():\n    Path('out').write_text('ok')",
  ]) {
    const r = inspect(source);
    assert.equal(r.semanticComplete, true, JSON.stringify(r.unresolved));
    assert.ok(files(r).some(([op, p]) => op === 'files.write' && p.endsWith('/out')));
  }
});
test('loop-carried paths, unknown iterators and element-dependent paths still require review', () => {
  for (const source of [
    "from pathlib import Path\nfor line in Path('input').read_text().splitlines():\n    Path(line).read_text()",
    "from pathlib import Path\np='a'\nwhile Path('flag').exists():\n    Path(p).read_text()\n    p=p+'x'",
    "from pathlib import Path\nfor line in unknown():\n    Path('a').read_text()",
  ])
    assert.equal(inspect(source).semanticComplete, false, source);
});
