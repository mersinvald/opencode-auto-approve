import { nativeTransport } from './native-transport.mjs';

const fileActions = new Set(['*', 'read', 'edit', 'external_directory', 'shell']);

export function normalizePermissionMetadata(event) {
  let visited = 0;
  const walk = (value, depth) => {
    if (value === null || typeof value !== 'object') return;
    if (++visited > 128 || depth > 12)
      throw Object.assign(Error('Permission metadata exceeds its shape budget'), {
        approvalCode: 'pending_lookup_invalid',
      });
    if (Array.isArray(value)) {
      for (const child of value) walk(child, depth + 1);
      return;
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) return;
    for (const key of Object.keys(value)) {
      if (value[key] === undefined) delete value[key];
      else walk(value[key], depth + 1);
    }
  };
  // Native hooks receive the host metadata object before it enters storage.
  // Omitted optional keys carry no value. Keep null, false, zero and empty strings.
  walk(event.metadata, 0);
}

export function pendingPermissionReader(ctx, { call = nativeTransport() } = {}) {
  return async (input, { signal } = {}) => {
    try {
      return await ctx.permission.get(input, { signal });
    } catch (error) {
      if (![error?.name, error?._tag, error?.code].includes('SchemaError')) throw error;
      // Try the native JSON API if only the SDK decoder failed. Malformed
      // host records can break both transports and must stop lookup retries.
      const invalid = () => {
        throw Object.assign(Error('Invalid native pending permission data'), {
          approvalCode: 'pending_lookup_invalid',
        });
      };
      let rows;
      try {
        rows = await call('GET', '/api/permission/request', {
          query: { 'location[directory]': ctx.location.directory },
          signal,
        });
      } catch {
        invalid();
      }
      if (!Array.isArray(rows)) invalid();
      const matches = rows.filter((r) => r?.id === input.requestID);
      if (!matches.length) return null;
      const r = matches[0];
      if (
        matches.length !== 1 ||
        r.sessionID !== input.sessionID ||
        typeof r.action !== 'string' ||
        !Array.isArray(r.resources) ||
        r.resources.some((x) => typeof x !== 'string') ||
        typeof r.message !== 'string' ||
        (r.metadata != null && (typeof r.metadata !== 'object' || Array.isArray(r.metadata))) ||
        (r.source != null &&
          (r.source.type !== 'tool' ||
            typeof r.source.id !== 'string' ||
            typeof r.source.messageID !== 'string'))
      )
        invalid();
      return r;
    }
  };
}

export function savedPermissionReader(ctx, options = {}) {
  const call = nativeTransport(options);
  return async (projectID, signal) => {
    const rows = ctx.permission.saved?.list
      ? await ctx.permission.saved.list({ projectID }, { signal })
      : await call('GET', '/api/permission/saved', { query: { projectID }, signal });
    if (
      !Array.isArray(rows) ||
      rows.some(
        (r) =>
          !r ||
          r.projectID !== projectID ||
          typeof r.id !== 'string' ||
          typeof r.action !== 'string' ||
          typeof r.resource !== 'string',
      )
    ) {
      throw new Error('Invalid saved OpenCode permissions');
    }
    // Shell grants do not provide blanket authorization for script effects.
    return rows
      .filter((r) => fileActions.has(r.action))
      .map(({ id, projectID, action, resource }) => ({ id, projectID, action, resource }))
      .sort((a, b) => a.id.localeCompare(b.id));
  };
}

export async function permissionEvidence(chain, saved, agent) {
  const projectID = chain[0].info.projectID;
  if (typeof projectID !== 'string' || !projectID)
    throw new Error('Missing native project identity');
  const rules = (value) => {
    if (value == null) return [];
    if (
      !Array.isArray(value) ||
      value.some(
        (r) =>
          !r ||
          typeof r.action !== 'string' ||
          typeof r.resource !== 'string' ||
          !['allow', 'ask', 'deny'].includes(r.effect),
      )
    ) {
      throw new Error('Invalid native permission rules');
    }
    return value.map(({ action, resource, effect }) => ({ action, resource, effect }));
  };
  return {
    projectID,
    saved: await saved(projectID),
    sessions: chain.map(({ info }) => ({
      sessionID: info.id,
      projectID: info.projectID,
      directory: info.location.directory,
      rules: rules(info.permissions),
    })),
    agent: agent ? { id: agent.id, rules: rules(agent.permissions) } : null,
  };
}
