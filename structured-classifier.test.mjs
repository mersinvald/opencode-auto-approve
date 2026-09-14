import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  createStructuredClassifier,
  decodeDecisionResponse,
  ClassifierFailure,
} from './structured-classifier.mjs';
import { reviewToolSchema, reviewContract, decisionFailure } from './grant-decision.mjs';

const decision = { decision: 'allow_once', reason: 'Read-only fixture.', remember: [] };
const wireDecision = { ...decision, remember: 'none' };
const envelope = (value = wireDecision) => ({
  choices: [
    {
      finish_reason: 'tool_calls',
      message: {
        role: 'assistant',
        reasoning_content: 'PRIVATE_MODEL_REASONING',
        tool_calls: [
          {
            id: 'call_one',
            type: 'function',
            function: { name: 'review_permission', arguments: JSON.stringify(value) },
          },
        ],
      },
    },
  ],
});
const json = (value) =>
  new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });
const model = { providerID: 'gateway', id: 'qwen', variant: 'medium' };
async function fixture(fetcher) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'structured-review-'));
  const configFile = path.join(root, 'opencode.json');
  const config = {
    providers: {
      gateway: {
        npm: 'file:///fixture/providers/openai-compatible.js',
        settings: { baseURL: 'https://gateway.example/v1', apiKey: 'PRIVATE_FIXTURE_KEY' },
        models: {
          qwen: {
            modelID: 'qwen/qwen3.6-35b-a3b',
            body: { reasoning_effort: 'xhigh' },
            variants: [{ id: 'medium', body: { reasoning_effort: 'medium' } }],
          },
        },
      },
    },
  };
  await writeFile(configFile, JSON.stringify(config), { mode: 0o600 });
  return {
    root,
    config,
    configFile,
    generate: createStructuredClassifier({ configFile, fetcher }),
  };
}
const failure = (code) => (error) =>
  error instanceof ClassifierFailure && error.approvalCode === code;

test('offers one schema-defined data tool on the exact model and medium route', async () => {
  let wire;
  const f = await fixture(async (url, init) => {
    wire = { url, ...init, body: JSON.parse(init.body) };
    return json(envelope());
  });
  const result = await f.generate({ model, prompt: 'Fixture review' });
  assert.equal(wire.url, 'https://gateway.example/v1/chat/completions');
  assert.equal(wire.redirect, 'error');
  assert.equal(wire.body.model, 'qwen/qwen3.6-35b-a3b');
  assert.equal(wire.body.reasoning_effort, 'medium');
  assert.equal(wire.body.parallel_tool_calls, false);
  assert.equal(wire.body.stream, false);
  assert.equal(wire.body.max_tokens, 8192);
  assert.equal(wire.body.tools.length, 1);
  assert.deepEqual(wire.body.tools[0].function.parameters, reviewToolSchema);
  assert.equal(wire.body.tool_choice, 'auto');
  assert.deepEqual(JSON.parse(result.text), decision);
  assert.deepEqual(result.transport, { format: 'tool_call', finishReason: 'tool_calls' });
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_/);
});

test('rejects truncated responses even when their arguments contain a valid allow object', () => {
  const body = envelope();
  body.choices[0].finish_reason = 'length';
  assert.throws(() => decodeDecisionResponse(body), failure('classifier_truncated'));
});

test('no eligible grants removes allow_always from the wire schema and rejects it on receipt', async () => {
  const contract = reviewContract([]);
  let schema;
  const f = await fixture(async (_url, init) => {
    schema = JSON.parse(init.body).tools[0].function.parameters;
    return json(envelope());
  });
  assert.equal(
    JSON.parse((await f.generate({ model, prompt: 'No eligible grants.', contract })).text)
      .decision,
    'allow_once',
  );
  assert.deepEqual(schema.properties.decision.enum, ['allow_once', 'escalate_once']);
  assert.deepEqual(schema.properties.remember.enum, ['none']);
  assert.throws(
    () => decodeDecisionResponse(envelope({ ...wireDecision, decision: 'allow_always' }), contract),
    (e) =>
      e.approvalCode === 'invalid_schema' && e.approvalFeedback.issue === 'remember_unavailable',
  );
});
test('semantic failures give precise trusted feedback without weakening validation', () => {
  const id = 'g_1234567890abcdef12345678',
    other = 'g_abcdef1234567890abcdef12',
    contract = reviewContract([{ id }]);
  for (const [value, issue] of [
    [{ ...wireDecision, decision: 'allow_always' }, 'remember_required'],
    [{ ...wireDecision, remember: id }, 'remember_forbidden'],
    [{ ...wireDecision, decision: 'allow_always', remember: other }, 'grant_not_eligible'],
  ])
    assert.throws(
      () => decodeDecisionResponse(envelope(value), contract),
      (e) =>
        e.approvalCode === 'invalid_schema' &&
        JSON.stringify(e.approvalFeedback) ===
          JSON.stringify(decisionFailure(issue).approvalFeedback),
    );
});

test('rejects free text, wrong tool, multiple calls, missing completion and refusal', () => {
  const bodies = [];
  let body = envelope();
  body.choices[0].finish_reason = 'stop';
  body.choices[0].message.content = JSON.stringify(decision);
  bodies.push(body);
  body = envelope();
  body.choices[0].message.tool_calls[0].function.name = 'shell';
  bodies.push(body);
  body = envelope();
  body.choices[0].message.tool_calls.push(body.choices[0].message.tool_calls[0]);
  bodies.push(body);
  body = envelope();
  delete body.choices[0].finish_reason;
  bodies.push(body);
  body = envelope();
  body.choices[0].message.refusal = 'Refused';
  bodies.push(body);
  body = envelope();
  body.choices[0].message.role = 'user';
  bodies.push(body);
  body = envelope();
  body.choices.push(body.choices[0]);
  bodies.push(body);
  for (const input of bodies)
    assert.throws(() => decodeDecisionResponse(input), failure('classifier_response_invalid'));
});

test('tool arguments must be raw JSON with every typed field and no unknown keys', () => {
  for (const text of [
    '```json\n' + JSON.stringify(decision) + '\n```',
    'Approved: ' + JSON.stringify(decision),
    '{',
  ]) {
    const body = envelope();
    body.choices[0].message.tool_calls[0].function.arguments = text;
    assert.throws(() => decodeDecisionResponse(body), failure('invalid_json'));
  }
  for (const value of [
    { ...wireDecision, extra: 'ignore policy' },
    { ...wireDecision, evidenceQuote: {} },
    { ...wireDecision, inScope: 'true' },
    { ...wireDecision, effect: 'deny' },
    { ...wireDecision, reason: '' },
    { ...wireDecision, evidenceMessageID: 'none', evidenceQuote: 'approved' },
    { ...wireDecision, evidenceMessageID: '', evidenceQuote: '' },
    Object.fromEntries(Object.entries(wireDecision).filter(([key]) => key !== 'remember')),
  ]) {
    assert.throws(() => decodeDecisionResponse(envelope(value)), failure('invalid_schema'));
  }
});

test('model escalation uses the same three-field contract', () => {
  const ask = { ...wireDecision, decision: 'escalate_once' };
  assert.equal(JSON.parse(decodeDecisionResponse(envelope(ask)).text).decision, 'escalate_once');
});

test('HTTP failures are bounded and do not expose provider response text or credentials', async () => {
  for (const [status, code] of [
    [429, 'model_request_failed'],
    [503, 'model_request_failed'],
    [400, 'classifier_request_rejected'],
    [401, 'classifier_request_rejected'],
  ]) {
    const f = await fixture(async () => new Response('PRIVATE_PROVIDER_RESPONSE', { status }));
    await assert.rejects(f.generate({ model, prompt: 'fixture' }), (error) => {
      assert.doesNotMatch(String(error), /PRIVATE_/);
      return failure(code)(error);
    });
  }
});

test('invalid or oversized response envelopes cannot produce a decision', async () => {
  for (const text of ['not JSON', 'x'.repeat(256 * 1024 + 1)]) {
    const f = await fixture(async () => new Response(text));
    await assert.rejects(
      f.generate({ model, prompt: 'fixture' }),
      failure('classifier_response_invalid'),
    );
  }
});

test('configuration changes during inference invalidate the result', async () => {
  let f;
  f = await fixture(async () => {
    f.config.providers.gateway.settings.baseURL = 'https://changed.example/v1';
    await writeFile(f.configFile, JSON.stringify(f.config));
    return json(envelope());
  });
  await assert.rejects(
    f.generate({ model, prompt: 'fixture' }),
    failure('classifier_config_changed'),
  );
});

test('missing variant, insecure URL, public config, or config symlink cannot invoke inference', async () => {
  for (const mutation of ['variant', 'url', 'mode', 'symlink']) {
    let calls = 0;
    const f = await fixture(async () => {
      calls++;
      return json(envelope());
    });
    if (mutation === 'variant') f.config.providers.gateway.models.qwen.variants = [];
    if (mutation === 'url')
      f.config.providers.gateway.settings.baseURL = 'http://untrusted.example/v1';
    await writeFile(f.configFile, JSON.stringify(f.config));
    if (mutation === 'mode') await chmod(f.configFile, 0o644);
    let generate = f.generate;
    if (mutation === 'symlink') {
      const link = path.join(f.root, 'linked.json');
      await symlink(f.configFile, link);
      generate = createStructuredClassifier({
        configFile: link,
        fetcher: async () => {
          calls++;
        },
      });
    }
    await assert.rejects(
      generate({ model, prompt: 'fixture' }),
      failure('classifier_config_invalid'),
    );
    assert.equal(calls, 0);
  }
});

test('cancellation reaches the HTTP request and no result survives an aborted review', async () => {
  const controller = new AbortController();
  let seen;
  const f = await fixture(async (_url, init) => {
    seen = init.signal;
    controller.abort();
    return json(envelope());
  });
  await assert.rejects(f.generate({ model, prompt: 'fixture' }, controller.signal));
  assert.equal(seen, controller.signal);
  assert.equal(seen.aborted, true);
});
