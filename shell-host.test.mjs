import test from 'node:test';
import assert from 'node:assert/strict';
import { captureShellRuntime } from './shell-host.mjs';
const event = (extra = {}) => ({
  command: 'cat file',
  cwd: '/fixture',
  shell: '/bin/bash',
  env: { PATH: '/usr/bin:/bin' },
  ...extra,
});
test('native tool capture survives sequential approval waits until completion', () => {
  let now = 0;
  const host = captureShellRuntime(() => now),
    e = event();
  host.begin('tool-a', e.command, e.cwd);
  host.capture(e);
  assert.ok(host.get(e.command, e.cwd, 'tool-a'));
  now = 17_000;
  assert.ok(host.get(e.command, e.cwd, 'tool-a'));
  now = 600_000;
  assert.ok(host.get(e.command, e.cwd, 'tool-a'));
  host.release(e.command, e.cwd, 'tool-a');
  assert.equal(host.get(e.command, e.cwd, 'tool-a'), null);
});
test('an orphan capture expires and cannot serve a different tool or changed command', () => {
  let now = 0;
  const host = captureShellRuntime(() => now),
    e = event();
  host.capture(e);
  now = 11_000;
  assert.equal(host.get(e.command, e.cwd, 'tool-a'), null);
  host.begin('tool-b', e.command, e.cwd);
  host.capture(e);
  assert.equal(host.get(e.command, e.cwd, 'tool-c'), null);
  assert.equal(host.get('cat other', e.cwd, 'tool-b'), null);
});
test('equal concurrent commands with different environments remain ambiguous', () => {
  const host = captureShellRuntime(),
    e = event();
  host.begin('a', e.command, e.cwd);
  host.begin('b', e.command, e.cwd);
  host.capture(e);
  host.capture(event({ env: { PATH: '/other' } }));
  assert.equal(host.get(e.command, e.cwd, 'a'), null);
  assert.equal(host.get(e.command, e.cwd, 'b'), null);
  host.release(e.command, e.cwd, 'a');
  assert.equal(host.get(e.command, e.cwd, 'b'), null);
  host.release(e.command, e.cwd, 'b');
  host.begin('c', e.command, e.cwd);
  host.capture(e);
  assert.ok(host.get(e.command, e.cwd, 'c'));
});
