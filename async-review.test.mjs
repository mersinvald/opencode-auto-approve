import test from 'node:test';
import assert from 'node:assert/strict';
import { createAsyncReview, fingerprint, pause } from './async-review.mjs';
const eventually = async (check) => {
  for (let i = 0; i < 200; i++) {
    if (check()) return;
    await pause(5);
  }
  throw Error('Condition timed out');
};
const allow = { effect: 'allow', code: 'model_allow' };
function fixture(options = {}) {
  const values = new Map(),
    pending = new Map(),
    log = [],
    replies = [];
  const storage = {
    get: async (k) => structuredClone(values.get(k)),
    set: async (k, v) => values.set(k, structuredClone(v)),
    remove: async (k) => values.delete(k),
  };
  const permission = {
    get: async ({ requestID }) => {
      if (!pending.has(requestID)) throw Error('404');
      return pending.get(requestID);
    },
    reply: async ({ requestID, reply }) => {
      if (!pending.has(requestID)) throw Error('404');
      pending.delete(requestID);
      replies.push({ requestID, reply });
    },
  };
  const dependencies = {
    storage,
    permission,
    review: async () => ({ result: allow }),
    audit: async (job, status, result) => log.push({ id: job.id, status, result }),
    preflight: async () => true,
    retryDelay: () => 5,
    ...options,
  };
  const q = createAsyncReview(dependencies);
  async function offer(id = 'per_one') {
    const event = { sessionID: 'ses_one', action: 'shell', resources: ['npm test'], effect: 'ask' };
    await q.offer(event, {});
    const request = { ...event, id };
    pending.set(id, request);
    await q.asked(request);
    return request;
  }
  return { q, offer, values, pending, log, replies, dependencies };
}
test('dialog exists before delayed model completion and auto reply is once only', async () => {
  let release;
  const f = fixture({
    review: () =>
      new Promise((resolve) => {
        release = () => resolve({ result: allow });
      }),
  });
  await f.offer();
  await eventually(() => release);
  assert.equal(f.pending.size, 1);
  assert.equal(f.replies.length, 0);
  release();
  await eventually(() => f.replies.length === 1);
  assert.equal(f.replies[0].reply, 'once');
  await f.q.stop();
});
test('next project request waits for confirmed rule save, unrelated projects do not', async () => {
  let confirm,
    save,
    finished = false;
  const f = fixture({
    review: async () => ({
      result: { ...allow, remember: [{ id: 'fixture' }], projectID: 'project-a' },
    }),
    audit: async (_job, status) => {
      if (status === 'allow')
        await new Promise((resolve) => {
          save = resolve;
        });
    },
  });
  const reply = f.dependencies.permission.reply;
  f.dependencies.permission.reply = async (args) => {
    await new Promise((resolve) => {
      confirm = resolve;
    });
    return reply(args);
  };
  await f.offer();
  await eventually(() => confirm);
  const waiting = f.q.settleRules('project-a').then(() => {
    finished = true;
  });
  await f.q.settleRules('project-b');
  assert.equal(finished, false);
  assert.equal(save, undefined);
  confirm();
  await eventually(() => save);
  assert.equal(finished, false);
  save();
  await waiting;
  assert.equal(f.replies.length, 1);
  await f.q.stop();
});
test('failed native reply releases the rule-save wait without saving a rule', async () => {
  let reject,
    saved = false;
  const f = fixture({
    review: async () => ({
      result: { ...allow, remember: [{ id: 'fixture' }], projectID: 'project-a' },
    }),
    audit: async (_job, status) => {
      if (status === 'allow') saved = true;
    },
  });
  f.dependencies.permission.reply = () =>
    new Promise((_resolve, r) => {
      reject = r;
    });
  await f.offer();
  await eventually(() => reject);
  const waiting = f.q.settleRules('project-a');
  reject(Error('Native reply lost'));
  await waiting;
  assert.equal(saved, false);
  await f.q.stop();
});
test('user rejection cancels the model and a late allow cannot override it', async () => {
  let release, signal;
  const f = fixture({
    review: (_job, s) => {
      signal = s;
      return new Promise((resolve) => {
        release = () => resolve({ result: allow });
      });
    },
  });
  await f.offer();
  await eventually(() => release);
  f.pending.delete('per_one');
  f.q.replied({ sessionID: 'ses_one', requestID: 'per_one', reply: 'reject' });
  assert.equal(signal.aborted, true);
  release();
  await f.q.stop();
  assert.equal(f.replies.length, 0);
  assert.equal(f.log.at(-1).status, 'native_reply');
});
test('transient failures retry without a final ASK, semantic ASK never retries', async () => {
  let calls = 0;
  const f = fixture({
    review: async () => ({
      result: ++calls < 3 ? { effect: 'ask', code: 'model_request_failed' } : allow,
    }),
  });
  await f.offer();
  await eventually(() => f.replies.length);
  assert.equal(calls, 3);
  assert.equal(f.log.filter((x) => x.status === 'retrying').length, 2);
  assert.ok(!f.log.some((x) => x.status === 'ask'));
  await f.q.stop();
  for (const code of [
    'model_escalation',
    'missing_explicit_authorization',
    'classifier_request_rejected',
    'classifier_config_invalid',
    'script_changed',
    'native_permissions_changed',
  ]) {
    let called = 0;
    const g = fixture({
      review: async () => {
        called++;
        return { result: { effect: 'ask', code } };
      },
    });
    await g.offer();
    await eventually(() => g.log.some((x) => x.status === 'ask'));
    assert.equal(called, 1);
    assert.equal(g.pending.size, 1);
    await g.q.stop();
  }
});
test('malformed and truncated decisions retry within a separate three-attempt budget', async () => {
  for (const code of [
    'invalid_json',
    'invalid_schema',
    'classifier_response_invalid',
    'classifier_truncated',
  ]) {
    let calls = 0;
    const f = fixture({
      review: async () => ({ result: ++calls === 1 ? { effect: 'ask', code } : allow }),
    });
    await f.offer();
    await eventually(() => f.replies.length);
    assert.equal(calls, 2);
    assert.equal(f.replies.length, 1);
    await f.q.stop();
    calls = 0;
    const g = fixture({
      review: async () => {
        calls++;
        return { result: { effect: 'ask', code } };
      },
    });
    await g.offer();
    await eventually(() => g.log.some((x) => x.result.code === 'classifier_format_exhausted'));
    assert.equal(calls, 3);
    assert.equal(g.replies.length, 0);
    assert.equal(g.pending.size, 1);
    await g.q.stop();
  }
});
test('format retry count survives a plugin restart', async () => {
  let calls = 0;
  const f = fixture({
    retryDelay: () => 10000,
    review: async () => {
      calls++;
      return { result: { effect: 'ask', code: 'invalid_json' } };
    },
  });
  const request = await f.offer();
  await eventually(() => f.log.some((x) => x.status === 'retrying'));
  await f.q.stop();
  assert.equal([...f.values.values()][0].formatAttempts, 1);
  for (const v of f.values.values()) v.next = 0;
  const recovered = createAsyncReview({ ...f.dependencies, retryDelay: () => 5 });
  await recovered.asked(request);
  await eventually(() => f.log.some((x) => x.result.code === 'classifier_format_exhausted'));
  assert.equal(calls, 3);
  assert.equal(f.replies.length, 0);
  await recovered.stop();
});
test('precise validation feedback survives restart and reaches the next attempt', async () => {
  const feedback = {
    issue: 'remember_unavailable',
    instruction: 'Use allow_once or escalate_once and remember none.',
  };
  const f = fixture({
    retryDelay: () => 10000,
    review: async () => ({ result: { effect: 'ask', code: 'invalid_schema', feedback } }),
  });
  const request = await f.offer();
  await eventually(() => f.log.some((x) => x.status === 'retrying'));
  await f.q.stop();
  assert.deepEqual([...f.values.values()][0].retryFeedback, feedback);
  for (const v of f.values.values()) v.next = 0;
  let received;
  const recovered = createAsyncReview({
    ...f.dependencies,
    review: async (job) => {
      received = job.meta.retryFeedback;
      return { result: allow };
    },
  });
  await recovered.asked(request);
  await eventually(() => f.replies.length === 1);
  assert.deepEqual(received, feedback);
  await recovered.stop();
});
test('queue limits concurrency and isolates identical requests by native request ID', async () => {
  let active = 0,
    peak = 0;
  const f = fixture({
    review: async () => {
      active++;
      peak = Math.max(peak, active);
      await pause(20);
      active--;
      return { result: allow };
    },
  });
  await Promise.all(Array.from({ length: 6 }, (_, i) => f.offer('per_' + i)));
  await eventually(() => f.replies.length === 6);
  assert.equal(peak, 2);
  assert.equal(new Set(f.replies.map((r) => r.requestID)).size, 6);
  await f.q.stop();
});
test('owned pending requests recover across reload, forged markers and changed requests cannot bind', async () => {
  let release;
  const f = fixture({
    review: () =>
      new Promise((resolve) => {
        release = () => resolve({ result: allow });
      }),
  });
  const request = await f.offer();
  await eventually(() => release);
  const stopping = f.q.stop();
  release();
  await stopping;
  assert.equal(f.replies.length, 0);
  const recovered = createAsyncReview({
    ...f.dependencies,
    review: async () => ({ result: allow }),
  });
  await recovered.asked({ ...request, resources: ['git push'] });
  assert.equal(recovered.size, 0);
  await recovered.asked({
    ...request,
    message: 'Automatic review [00000000-0000-0000-0000-000000000000] is pending.',
  });
  assert.equal(recovered.size, 0);
  await recovered.asked(request);
  await eventually(() => f.replies.length);
  await recovered.stop();
});
test('native revalidation and audit failures prevent automatic replies', async () => {
  for (const opts of [
    { preflight: async () => false },
    {
      audit: async () => {
        throw Error('Disk full');
      },
    },
  ]) {
    const f = fixture(opts);
    await f.offer();
    await eventually(() => f.q.size === 0);
    assert.equal(f.replies.length, 0);
    assert.equal(f.pending.size, 1);
    await f.q.stop();
  }
});
test('a user response that wins the reply race is not recorded as a model grant', async () => {
  const f = fixture();
  f.dependencies.permission.reply = async () => {
    f.pending.delete('per_one');
    throw Error('404');
  };
  await f.offer();
  await eventually(() => f.log.some((x) => x.status === 'resolved'));
  assert.ok(!f.log.some((x) => x.status === 'allow'));
  await f.q.stop();
});
test('retry budgets survive reload and expired requests keep the user dialog', async () => {
  const f = fixture({
    maxAttempts: 2,
    review: async () => ({ result: { effect: 'ask', code: 'model_request_failed' } }),
  });
  await f.offer();
  await eventually(() => f.log.some((x) => x.result.code === 'retry_exhausted'));
  assert.equal(f.pending.size, 1);
  assert.equal(f.replies.length, 0);
  await f.q.stop();
});
test('fingerprint binds metadata and exact tool source', () => {
  const e = {
    sessionID: 'ses_one',
    action: 'shell',
    resources: ['npm test'],
    source: { id: 'call_a' },
  };
  assert.notEqual(fingerprint(e), fingerprint({ ...e, source: { id: 'call_b' } }));
  assert.notEqual(fingerprint(e), fingerprint({ ...e, metadata: { resource: 'elsewhere' } }));
});
test('event recovery races bind one job and never run duplicate classifier calls', async () => {
  let calls = 0;
  const f = fixture({
    review: async () => {
      calls++;
      await pause(15);
      return { result: allow };
    },
  });
  const event = { sessionID: 'ses_one', action: 'shell', resources: ['npm test'], effect: 'ask' };
  await f.q.offer(event, {});
  const request = { ...event, id: 'per_race' };
  f.pending.set(request.id, request);
  await Promise.all([f.q.asked(request), f.q.asked(request), f.q.asked(request)]);
  await eventually(() => f.replies.length === 1);
  assert.equal(calls, 1);
  await f.q.stop();
});
test('another project context cannot process or remove a shared storage ticket', async () => {
  const f = fixture({ owner: { directory: '/project/a', workspaceID: null } });
  const event = { sessionID: 'ses_one', action: 'shell', resources: ['npm test'], effect: 'ask' };
  await f.q.offer(event, { directory: '/project/a' });
  const request = { ...event, id: 'per_owned' };
  f.pending.set(request.id, request);
  const foreign = createAsyncReview({
    ...f.dependencies,
    owner: { directory: '/project/b', workspaceID: null },
    permission: {
      get: async () => {
        throw Error('Foreign context must not fetch this request');
      },
    },
    review: async () => {
      throw Error('Foreign context must not run the classifier');
    },
  });
  await foreign.asked(request);
  assert.equal(foreign.size, 0);
  assert.equal(f.values.size, 1);
  assert.equal(f.log.length, 0);
  await f.q.asked(request);
  await eventually(() => f.replies.length === 1);
  await foreign.stop();
  await f.q.stop();
});

test('pending lookup errors retry before and after review without abandoning the dialog', async () => {
  for (const failingCall of [1, 2]) {
    let reads = 0,
      reviews = 0;
    const f = fixture({
      review: async () => {
        reviews++;
        return { result: allow };
      },
    });
    const get = f.dependencies.permission.get;
    f.dependencies.permission.get = async (x) => {
      if (++reads === failingCall)
        throw Object.assign(Error('Native lookup temporarily unavailable'), { code: 'ECONNRESET' });
      return get(x);
    };
    await f.offer();
    await eventually(() => f.replies.length === 1);
    const retry = f.log.find((x) => x.result.code === 'pending_lookup_failed');
    assert.equal(retry.status, 'retrying');
    assert.equal(retry.result.diagnostic.code, 'ECONNRESET');
    assert.equal(reviews, failingCall === 1 ? 1 : 2);
    assert.ok(!f.log.some((x) => x.status === 'resolved'));
    await f.q.stop();
  }
});
test('lookup retry budget survives restart and leaves a bounded final ASK', async () => {
  const f = fixture({ maxAttempts: 2, retryDelay: () => 10000 });
  f.dependencies.permission.get = async () => {
    throw Error('Lookup failed');
  };
  const request = await f.offer();
  await eventually(() => f.log.some((x) => x.status === 'retrying'));
  await f.q.stop();
  assert.equal([...f.values.values()][0].lookupAttempts, 1);
  for (const v of f.values.values()) v.next = 0;
  const recovered = createAsyncReview({ ...f.dependencies, retryDelay: () => 5 });
  await recovered.asked(request);
  await eventually(() => f.log.some((x) => x.result.code === 'pending_lookup_exhausted'));
  assert.equal(f.replies.length, 0);
  assert.equal(f.pending.size, 1);
  assert.equal(f.values.size, 0);
  await recovered.stop();
});
test('user response during a failing lookup cannot produce a late retry', async () => {
  let reject;
  const f = fixture();
  f.dependencies.permission.get = () =>
    new Promise((_resolve, r) => {
      reject = r;
    });
  await f.offer();
  await eventually(() => reject);
  f.q.replied({ sessionID: 'ses_one', requestID: 'per_one', reply: 'reject' });
  reject(Error('cancelled lookup'));
  await f.q.stop();
  assert.equal(f.log.at(-1).status, 'native_reply');
  assert.ok(!f.log.some((x) => x.status === 'retrying'));
  assert.equal(f.replies.length, 0);
});
test('permanent pending schema errors stop immediately, absent requests resolve without ASK', async () => {
  for (const absent of [false, true]) {
    const f = fixture();
    let calls = 0;
    f.dependencies.permission.get = async () => {
      calls++;
      if (absent) return null;
      throw Object.assign(Error('bad metadata'), { name: 'SchemaError' });
    };
    await f.offer();
    await eventually(() => f.log.some((x) => x.status === (absent ? 'resolved' : 'ask')));
    assert.equal(calls, 1);
    assert.equal(f.replies.length, 0);
    assert.equal(f.log.at(-1).result.code, absent ? 'pending_gone' : 'pending_lookup_invalid');
    await f.q.stop();
  }
});
test('native answer after model escalation gets a final audit record', async () => {
  const f = fixture({
    review: async () => ({ result: { effect: 'ask', code: 'model_escalation' } }),
  });
  await f.offer();
  await eventually(() => f.log.some((x) => x.status === 'ask'));
  f.q.replied({ sessionID: 'ses_one', requestID: 'per_one', reply: 'once' });
  await eventually(() => f.log.at(-1).status === 'native_reply');
  assert.equal(f.log.at(-1).result.effect, 'allow');
  assert.equal(f.replies.length, 0);
  await f.q.stop();
});
