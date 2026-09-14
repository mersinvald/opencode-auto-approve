import test from 'node:test';
import assert from 'node:assert/strict';
import { stripVTControlCharacters } from 'node:util';
import { terminalOptions, terminalLayout, textWidth } from './audit-terminal.mjs';
import { formatDetailedRecord } from './audit-view.mjs';

const row = {
  time: '2026-09-14T13:00:00Z',
  action: 'shell',
  mode: 'enforce',
  applied: 'allow',
  code: 'model_rules_saved',
  status: 'scoped_grant_created',
  sessionID: 'ses_terminal_fixture',
  preview: 'cat /fixture/worktree/src/Документ.md',
  reason: 'Authorized local edit.',
  elapsedMs: 1120,
};
const item = {
  id: 'fixture',
  operation: 'files.write',
  target: 'src/Документ.md',
  targetType: 'file',
  repositoryName: 'infra',
  space: { repository: 'a'.repeat(64), modifier: 'scratch' },
  binding: { root: '/fixture/worktree' },
};
const data = {
  grants: { complete: true, entries: [{ grant: item, mode: 'dynamic' }] },
  lifecycle: {
    ruleUpdate: {
      status: 'saved',
      changes: [{ before: null, after: { ...item, mode: 'allow' } }],
      before: [{ grant: item, mode: 'dynamic' }],
      after: [{ grant: item, mode: 'allow' }],
    },
  },
};

test('automatic color respects TTY, NO_COLOR and dumb terminals; explicit choices override', () => {
  const tty = { stream: { isTTY: true }, env: { TERM: 'xterm-256color' } };
  assert.equal(terminalOptions(tty).color, true);
  assert.equal(terminalOptions({ ...tty, stream: {} }).color, false);
  assert.equal(terminalOptions({ ...tty, env: { NO_COLOR: '' } }).color, false);
  assert.equal(terminalOptions({ ...tty, env: { TERM: 'dumb' } }).color, false);
  assert.equal(terminalOptions({ ...tty, color: 'never' }).color, false);
  assert.equal(
    terminalOptions({ stream: {}, env: { NO_COLOR: '1' }, color: 'always' }).color,
    true,
  );
});

test('details wrap within narrow and wide terminals without losing grant or transition text', () => {
  for (const width of [32, 40, 72, 100, 140]) {
    const text = stripVTControlCharacters(
      formatDetailedRecord({ ...row, detail: { data } }, { width, color: 'always' }),
    );
    for (const line of text.split('\n')) assert.ok(textWidth(line) <= width, `${width}: ${line}`);
    const compact = text.replace(/\s/g, '');
    for (const expected of [
      'No exact rule → Always allow',
      'Dynamic → Always allow',
      'files.write',
      'infra:scratch/src/Документ.md',
    ]) {
      assert.ok(compact.includes(expected.replace(/\s/g, '')), expected);
    }
    assert.doesNotMatch(text, / +\n/);
  }
  const ui = terminalLayout({ width: 32, color: 'never' });
  ui.line('文档/🙂/e\u0301/'.repeat(12));
  for (const line of ui.result().split('\n')) assert.ok(textWidth(line) <= 32);
  assert.ok(ui.result().includes('e\u0301'));
});

test('status and grant colors are semantic; untrusted content cannot inject terminal controls', () => {
  for (const [applied, label, code] of [
    ['allow', 'APPROVED', 32],
    ['ask', 'APPROVAL NEEDED', 33],
    ['deny', 'DENIED', 31],
  ]) {
    const text = formatDetailedRecord({ ...row, applied, detail: { data } }, { color: 'always' });
    assert.ok(text.includes(`\x1b[${code}m${label}`));
    assert.match(text, /\x1b\[36m\s+Dynamic\s+files.write/);
    assert.match(text, /\x1b\[32m\s+Dynamic → Always allow/);
  }
  const unsafe = { ...row, reason: '\x1b[5mblink\x1b]52;c;payload\x07', preview: '\x1b[2Jclear' };
  const text = formatDetailedRecord(unsafe, { color: 'always' });
  assert.doesNotMatch(text, /\x1b\[5m|\x1b\]52|\x1b\[2J/);
  assert.doesNotMatch(stripVTControlCharacters(text), /\x1b|\x07/);
});

test('worktree display aliases preserve sibling paths and distinguish same-name repositories', () => {
  const other = {
    ...item,
    binding: { root: '/fixture/other' },
    space: { ...item.space, repository: 'b'.repeat(64) },
  };
  const text = formatDetailedRecord(
    {
      ...row,
      preview: 'cat /fixture/worktree/src/a /fixture/worktree-other/src/b /fixture/other/src/c',
      detail: {
        data: {
          grants: {
            complete: true,
            entries: [
              { grant: item, mode: 'allow' },
              { grant: other, mode: 'allow' },
            ],
          },
        },
      },
    },
    { width: 100, color: 'never' },
  );
  assert.match(text, /@infra\/src\/a/);
  assert.match(text, /\/fixture\/worktree-other\/src\/b/);
  assert.match(text, /@infra-2\/src\/c/);
  assert.match(text, /@infra = \/fixture\/worktree/);
  assert.match(text, /@infra-2 = \/fixture\/other/);
  assert.match(text, /infra-2:scratch\/src\/Документ.md/);
  assert.match(text, /infra:scratch = linked worktrees of repository aaaaaaaa/);
  assert.match(text, /infra-2:scratch = linked worktrees of repository bbbbbbbb/);
});
