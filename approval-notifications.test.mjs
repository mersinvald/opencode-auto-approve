import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, readdir, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  WAIT_MS,
  notificationReason,
  notificationOptions,
  notifyMac,
  deliverOnce,
  createApprovalNotifications,
} from './approval-notifications.mjs';

const epoch = Date.parse('2026-09-13T10:00:00Z');
const row = (fields = {}) => ({
  version: 3,
  time: new Date(epoch).toISOString(),
  sessionID: 'ses_worker',
  requestID: 'per_test',
  sourceID: 'call_test',
  action: 'shell',
  mode: 'enforce',
  status: 'reviewing',
  applied: 'pending',
  elapsedMs: 0,
  code: 'review_in_progress',
  ...fields,
});
const request = {
  id: 'per_test',
  sessionID: 'ses_worker',
  action: 'shell',
  source: { id: 'call_test' },
};

async function fixture(t, initial = row()) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'approval-notifications-'));
  const policyFile = path.join(root, 'policy.json');
  await writeFile(policyFile, JSON.stringify({ auditRoot: root }));
  const f = {
    clock: epoch,
    rows: [initial],
    requests: [request],
    sends: [],
    warnings: [],
    checks: 0,
  };
  f.options = {
    policyFile,
    now: () => f.clock,
    platform: 'darwin',
    records: async () => f.rows,
    notify: async (value) => {
      f.sends.push(value);
      return { notification: true };
    },
    onError: (value) => f.warnings.push(value),
    client: {
      permission: {
        list: async () => {
          f.checks++;
          return f.requests;
        },
      },
    },
  };
  f.monitor = createApprovalNotifications(f.options);
  t.after(() => f.monitor.stop());
  return f;
}

test('a silent review crosses the five-minute boundary without another audit event', async (t) => {
  const f = await fixture(t);
  await f.monitor.tick();
  f.clock += WAIT_MS - 1;
  await f.monitor.tick();
  assert.equal(f.sends.length, 0);
  f.clock++;
  await f.monitor.tick();
  assert.equal(f.sends.length, 1);
  assert.match(f.sends[0].message, /5 minutes/);
  f.rows = [row({ applied: 'ask', status: 'ask', code: 'model_escalation' })];
  await f.monitor.tick();
  assert.equal(f.sends.length, 1, 'later escalation does not repeat the same pending alert');
});

test('retry timestamps preserve original elapsed time and recovery after TUI restart', async (t) => {
  const f = await fixture(
    t,
    row({
      time: new Date(epoch + 270000).toISOString(),
      elapsedMs: 270000,
      status: 'retrying',
      code: 'review_timeout',
    }),
  );
  f.clock = epoch + WAIT_MS;
  await f.monitor.tick();
  assert.equal(f.sends.length, 1);
  const other = createApprovalNotifications(f.options);
  await other.tick();
  other.stop();
  assert.equal(f.sends.length, 1, 'disk receipts survive instance replacement');
});

test('escalation and terminal failure notify immediately, recoverable invalid JSON waits', async (t) => {
  for (const code of [
    'model_escalation',
    'classifier_format_exhausted',
    'async_review_failed',
    'preparation_failed',
  ]) {
    const f = await fixture(t, row({ code, status: 'ask', applied: 'ask' }));
    await f.monitor.tick();
    assert.equal(f.sends.length, 1, code);
  }
  assert.equal(notificationReason(row({ status: 'retrying', code: 'invalid_json' }), epoch), null);
  assert.equal(
    notificationReason(row({ status: 'resolved', code: 'reply_not_confirmed' }), epoch),
    'review_failed',
  );
});

test('known-safe, shadow, denied, saved-grant and user-reply records never notify', () => {
  for (const fields of [
    { applied: 'allow' },
    { applied: 'deny' },
    { mode: 'shadow', applied: 'ask' },
    { status: 'native_reply', applied: 'ask' },
    { action: 'scoped_permission', applied: 'ask' },
  ]) {
    assert.equal(notificationReason(row(fields), epoch + WAIT_MS), null);
  }
});

test('a resolved request does not notify from an old ASK audit', async (t) => {
  const f = await fixture(t, row({ applied: 'ask', status: 'ask' }));
  f.requests = [];
  await f.monitor.tick();
  assert.equal(f.sends.length, 0);
});

test('a request that disappeared during review does not become a failure notification', async (t) => {
  const latest = row({ status: 'resolved', code: 'pending_gone' });
  assert.equal(notificationReason(latest, epoch + WAIT_MS), null);
  const f = await fixture(t, row({ status: 'ask', applied: 'ask' }));
  let reads = 0;
  const monitor = createApprovalNotifications({
    ...f.options,
    records: async () => (++reads === 1 ? f.rows : [latest]),
  });
  await monitor.tick();
  monitor.stop();
  assert.equal(f.sends.length, 0);
});

test('native user response between discovery and delivery cancels the notification', async (t) => {
  const f = await fixture(t, row({ applied: 'ask', status: 'ask' }));
  f.options.client.permission.list = async () => (++f.checks === 1 ? [request] : []);
  await f.monitor.tick();
  assert.equal(f.sends.length, 0);
  assert.equal(f.warnings.length, 0);
});

test('fresh review or ALLOW between discovery and delivery cancels a stale ASK', async (t) => {
  for (const latest of [row(), row({ status: 'allow', applied: 'allow' })]) {
    const f = await fixture(t, row({ status: 'ask', applied: 'ask' }));
    let reads = 0;
    const monitor = createApprovalNotifications({
      ...f.options,
      records: async () => (++reads === 1 ? f.rows : [latest]),
    });
    await monitor.tick();
    monitor.stop();
    assert.equal(f.sends.length, 0);
  }
});

test('notifications find hidden worker sessions and bind source-only preparation failures', async (t) => {
  const f = await fixture(
    t,
    row({
      version: 2,
      requestID: undefined,
      status: undefined,
      applied: 'ask',
      code: 'preparation_failed',
    }),
  );
  const seen = [];
  f.options.client.permission.list = async ({ sessionID }) => {
    seen.push(sessionID);
    return [request];
  };
  await f.monitor.tick();
  assert.equal(f.sends.length, 1);
  assert.deepEqual(seen, ['ses_worker', 'ses_worker']);
});

test('a different native source cannot receive a source-only audit notification', async (t) => {
  const f = await fixture(
    t,
    row({ version: 2, requestID: undefined, applied: 'ask', status: undefined }),
  );
  f.requests = [{ ...request, source: { id: 'other' } }];
  await f.monitor.tick();
  assert.equal(f.sends.length, 0);
});

test('multiple TUIs cannot send duplicate notifications concurrently', async (t) => {
  const f = await fixture(t, row({ status: 'ask', applied: 'ask' }));
  const other = createApprovalNotifications(f.options);
  await Promise.all([other.tick(), f.monitor.tick(), f.monitor.tick()]);
  other.stop();
  assert.equal(f.sends.length, 1);
});

test('failed or disabled native notifications retry after a minute without affecting permissions', async (t) => {
  const f = await fixture(t, row({ status: 'ask', applied: 'ask' }));
  let attempts = 0;
  const monitor = createApprovalNotifications({
    ...f.options,
    notify: async () => {
      attempts++;
      if (attempts === 1) throw Error('Unavailable');
      return { notification: attempts > 2 };
    },
  });
  await monitor.tick();
  await monitor.tick();
  assert.equal(attempts, 1);
  f.clock += 60000;
  await monitor.tick();
  await monitor.tick();
  assert.equal(attempts, 2);
  f.clock += 60000;
  await monitor.tick();
  await monitor.tick();
  assert.equal(attempts, 3);
  assert.equal(f.requests.length, 1);
  monitor.stop();
});

test('the interval checks silent requests and disposal stops notifications', async (t) => {
  const f = await fixture(t);
  let callback,
    cleared = false;
  const monitor = createApprovalNotifications({
    ...f.options,
    schedule: (fn) => {
      callback = fn;
      return 1;
    },
    unschedule: (id) => {
      assert.equal(id, 1);
      cleared = true;
    },
  });
  monitor.start();
  await new Promise((r) => setImmediate(r));
  assert.equal(typeof callback, 'function');
  monitor.stop();
  f.clock += WAIT_MS;
  callback();
  await monitor.tick();
  assert.equal(cleared, true);
  assert.equal(f.sends.length, 0);
});

test('notification body excludes script text, resources and model comments', () => {
  const value = notificationOptions(
    {
      ...request,
      resources: ['secret-script'],
      message: 'sensitive model content',
      action: 'shell\u001b[31m',
    },
    'review_escalated',
  );
  assert.doesNotMatch(JSON.stringify(value), /secret-script|sensitive model|\\u001b/);
  assert.equal(value.notification.when, 'always');
});

test('receipt store uses private files, avoids symlinks, and releases cancelled sends', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'approval-receipts-'));
  assert.equal(await deliverOnce(root, 'cancelled', async () => null), 'cancelled');
  assert.deepEqual(await readdir(path.join(root, 'notifications')), []);
  assert.equal(await deliverOnce(root, 'sent', async () => ({ notification: true })), 'sent');
  const file = (await readdir(path.join(root, 'notifications')))[0];
  assert.equal(
    JSON.parse(await readFile(path.join(root, 'notifications', file), 'utf8')).status,
    'sent',
  );
  const unsafe = await mkdtemp(path.join(os.tmpdir(), 'approval-receipts-link-'));
  await symlink(path.join(root, 'notifications'), path.join(unsafe, 'notifications'));
  await assert.rejects(
    deliverOnce(unsafe, 'unsafe', async () => ({ notification: true })),
    /Unsafe/,
  );
});

test('macOS fallback passes untrusted text as data and has a bounded execution time', async () => {
  const options = {
    title: 'title " & do shell script "bad',
    message: '$(touch /tmp/never)\n"\\secret',
  };
  let call;
  const result = await notifyMac(
    { notify: async () => ({ notification: false, sound: true }) },
    options,
    {
      platform: 'darwin',
      execute: async (...args) => {
        call = args;
      },
    },
  );
  assert.equal(result.notification, true);
  assert.equal(result.transport, 'macos');
  assert.equal(call[0], '/usr/bin/osascript');
  assert.deepEqual(call[1].slice(2), [options.title, options.message]);
  assert.doesNotMatch(call[1][1], /secret|touch|do shell script/);
  assert.equal(call[2].timeout, 5000);
  assert.equal(call[2].shell, undefined);
});

test('native success or disabled attention never invokes the macOS fallback', async () => {
  for (const result of [
    { notification: true },
    { notification: false, skipped: 'attention_disabled' },
    { notification: false, skipped: 'renderer_destroyed' },
  ]) {
    assert.deepEqual(
      await notifyMac(
        { notify: async () => result },
        {},
        {
          platform: 'darwin',
          execute: async () => assert.fail('Unexpected fallback'),
        },
      ),
      result,
    );
  }
});

test('macOS fallback respects the saved notification toggle', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'approval-notification-toggle-'));
  await writeFile(
    path.join(root, 'cli.json'),
    JSON.stringify({ attention: { enabled: true, notifications: false } }),
  );
  const result = await notifyMac(
    { notify: async () => ({ notification: false, sound: true }) },
    {},
    {
      policyFile: path.join(root, 'approval-policy.json'),
      platform: 'darwin',
      execute: async () => assert.fail('Notifications are disabled'),
    },
  );
  assert.equal(result.notification, false);
});
