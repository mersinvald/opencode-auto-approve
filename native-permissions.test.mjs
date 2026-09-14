import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  savedPermissionReader,
  pendingPermissionReader,
  normalizePermissionMetadata,
  permissionEvidence,
} from './native-permissions.mjs';
import { loadEvidence } from './review-context.mjs';
import { secretPath, policyPath } from './policy.mjs';

const rows = [
  { id: 'edit', projectID: 'pwa', action: 'edit', resource: '*' },
  { id: 'infra', projectID: 'pwa', action: 'external_directory', resource: '/workspace/infra/*' },
  { id: 'shell', projectID: 'pwa', action: 'shell', resource: 'python3 *' },
];
const info = {
  id: 'root',
  projectID: 'pwa',
  location: { directory: '/workspace/pwa' },
  permissions: [],
};
const users = [{ id: 'user', type: 'user', text: 'Migrate beads in the affected repositories.' }];
const session = { get: async () => info, context: async () => users };
const native = {
  saved: savedPermissionReader({ permission: { saved: { list: async () => rows } } }),
};
const config = {
  version: 1,
  mode: 'enforce',
  model: { providerID: 'fixture', id: 'review', variant: 'medium' },
  skillRoots: [],
  protectedRoots: [],
  scratchRoot: '/private/tmp/approval-fixture-scratch',
  auditRoot: '/private/tmp/approval-fixture-audit',
  timeoutMs: 500,
  maxRequestChars: 32000,
};
const allow = {
  effect: 'allow',
  consequence: 'local_write',
  inScope: true,
  authorization: 'task',
  evidence: null,
  reason: 'Routine task edits.',
};

test('saved grants from another project and malformed rules fail closed', async () => {
  for (const saved of [[{ ...rows[0], projectID: 'unrelated' }], [{}], { rows }]) {
    await assert.rejects(
      savedPermissionReader({ permission: { saved: { list: async () => saved } } })('pwa'),
    );
  }
  await assert.rejects(
    permissionEvidence(
      [{ info: { ...info, permissions: [{ action: 'edit', effect: 'allow' }] } }],
      async () => [],
    ),
  );
});

test('parent restrictions are retained without importing the parent project grants', async () => {
  let requested;
  const proof = await permissionEvidence(
    [
      { info: { ...info, parentID: 'parent' } },
      {
        info: {
          ...info,
          id: 'parent',
          projectID: 'different',
          permissions: [{ action: 'edit', resource: '/workspace/infra/*', effect: 'deny' }],
        },
      },
    ],
    async (id) => {
      requested = id;
      return rows;
    },
    { id: 'reviewer', permissions: [{ action: 'edit', resource: '*', effect: 'deny' }] },
  );
  assert.equal(requested, 'pwa');
  assert.equal(proof.sessions[1].rules[0].effect, 'deny');
  assert.equal(proof.agent.rules[0].effect, 'deny');
});
test('SDK metadata schema errors recover through verified native JSON request identity', async () => {
  const input = { sessionID: 'ses_a', requestID: 'per_a' },
    row = {
      id: 'per_a',
      sessionID: 'ses_a',
      action: 'grep',
      resources: ['needle'],
      metadata: { path: '/fixture/file' },
      message: 'review',
      source: { type: 'tool', id: 'call_a', messageID: 'msg_a' },
    };
  const ctx = {
    location: { directory: '/fixture' },
    permission: {
      get: async () => {
        throw Object.assign(Error('Expected JSON value at metadata.include'), {
          _tag: 'SchemaError',
        });
      },
    },
  };
  let calls = 0;
  const read = pendingPermissionReader(ctx, {
    call: async (method, url, { query }) => {
      calls++;
      assert.equal(method, 'GET');
      assert.equal(url, '/api/permission/request');
      assert.equal(query['location[directory]'], '/fixture');
      return [row];
    },
  });
  assert.deepEqual(await read(input), row);
  assert.equal(calls, 1);
  for (const data of [
    [{ ...row, sessionID: 'ses_other' }],
    [{ ...row, resources: [undefined] }],
    [row, row],
    {},
  ])
    await assert.rejects(
      pendingPermissionReader(ctx, { call: async () => data })(input),
      (e) => e.approvalCode === 'pending_lookup_invalid',
    );
  assert.equal(await pendingPermissionReader(ctx, { call: async () => [] })(input), null);
  await assert.rejects(
    pendingPermissionReader(
      {
        ...ctx,
        permission: {
          get: async () => {
            throw Error('network down');
          },
        },
      },
      {
        call: async () => {
          throw Error('must not call');
        },
      },
    )(input),
    /network down/,
  );
});
test('native optional metadata is normalized before storage without changing request or meaningful values', () => {
  const event = {
    resources: ['needle'],
    metadata: {
      path: '/fixture/file',
      include: undefined,
      limit: 0,
      empty: '',
      value: null,
      off: false,
      nested: { omit: undefined, keep: 'value' },
    },
  };
  const before = JSON.stringify(event);
  normalizePermissionMetadata(event);
  assert.equal(JSON.stringify(event), before);
  assert.equal(Object.hasOwn(event.metadata, 'include'), false);
  assert.deepEqual(event.metadata, {
    path: '/fixture/file',
    limit: 0,
    empty: '',
    value: null,
    off: false,
    nested: { keep: 'value' },
  });
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => normalizePermissionMetadata({ metadata: cyclic }));
});

test('discovery adapter uses authenticated loopback, the same process, bounded data and no redirects', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'approval-permissions-'));
  const file = path.join(dir, 'service.json');
  const service = { url: 'http://127.0.0.1:12345', pid: process.pid, password: 'fixture-only' };
  const save = async (value) => writeFile(file, JSON.stringify(value), { mode: 0o600 });
  await save(service);
  let calls = 0;
  const fetcher = async (url, options) => {
    calls++;
    assert.equal(url.href, 'http://127.0.0.1:12345/api/permission/saved?projectID=pwa');
    assert.equal(options.redirect, 'error');
    assert.equal(
      options.headers.Authorization,
      'Basic ' + Buffer.from('opencode:fixture-only').toString('base64'),
    );
    return new Response(JSON.stringify({ data: rows }));
  };
  const read = savedPermissionReader({ permission: {} }, { serviceFile: file, fetcher });
  assert.deepEqual(await read('pwa'), rows);
  for (const update of [
    { pid: process.pid + 1 },
    { url: 'https://example.org' },
    { url: 'http://127.0.0.1:12345/other' },
    { url: 'http://name:password@127.0.0.1:12345' },
  ]) {
    await save({ ...service, ...update });
    await assert.rejects(read('pwa'));
  }
  assert.equal(calls, 1);
  await save(service);
  await chmod(file, 0o644);
  await assert.rejects(read('pwa'));
  await chmod(file, 0o600);
  await symlink(file, file + '.link');
  await assert.rejects(
    savedPermissionReader({ permission: {} }, { serviceFile: file + '.link', fetcher })('pwa'),
  );
  await assert.rejects(
    savedPermissionReader(
      { permission: {} },
      { serviceFile: file, fetcher: async () => new Response(' '.repeat(256 * 1024 + 1)) },
    )('pwa'),
  );
});
