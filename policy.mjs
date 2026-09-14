import { createHash } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';

export const VERSION = 1;
export const digest = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
export const within = (target, root) =>
  target === root || target.startsWith(root === '/' ? '/' : root + path.sep);
export const requestDirectory = (request) =>
  path.resolve(
    request.directory ?? '.',
    request.tool?.input?.workdir || request.tool?.input?.cwd || '.',
  );

export async function canonical(target, cwd) {
  if (typeof target !== 'string' || !target || /[\0\r\n]/.test(target))
    throw new Error('Invalid path');
  // Permission boundaries end in /*. No other wildcard denotes a concrete path.
  const clean = target.endsWith('/*') ? target.slice(0, -2) : target;
  if (/[?*\[\]{}]/.test(clean)) throw new Error('Unresolved path pattern');
  let current = path.resolve(cwd, clean);
  const suffix = [];
  for (let i = 0; i < 100; i++) {
    try {
      const stat = await lstat(current);
      // realpath must reject dangling links instead of treating them as new paths.
      const base = await realpath(current);
      if (suffix.length && !stat.isDirectory() && !stat.isSymbolicLink())
        throw new Error('Non-directory ancestor');
      return path.join(base, ...suffix.reverse());
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      try {
        if ((await lstat(current)).isSymbolicLink()) throw new Error('Dangling symlink');
      } catch (e) {
        if (e.code !== 'ENOENT') throw e;
      }
      const parent = path.dirname(current);
      if (parent === current) throw error;
      suffix.push(path.basename(current));
      current = parent;
    }
  }
  throw new Error('Path depth exceeded');
}

export function sensitivePath(p, protectedRoots = []) {
  return (
    protectedRoots.some((root) => within(p, root)) ||
    /(?:^|\/)\.git(?:\/|$)/.test(p) ||
    secretPath(p)
  );
}
export function secretPath(p) {
  return (
    /(?:^|\/)(?:\.ssh|\.aws|\.kube|\.gnupg|\.docker)(?:\/|$)/.test(p) ||
    /(?:^|\/)(?:\.env(?:\.[^/]*)?|auth\.json|credentials(?:\.[^/]*)?|id_rsa|id_ed25519)(?:\/|$)/.test(
      p,
    ) ||
    /\/opencode\/service\.json$/.test(p)
  );
}
export function policyPath(p, protectedRoots = []) {
  return (
    protectedRoots.some((root) => within(p, root)) ||
    /(?:^|\/)(?:AGENTS\.md|CLAUDE\.md|SKILL\.md|opencode\.jsonc?|\.opencode|\.git)(?:\/|$)/i.test(
      p,
    ) ||
    /(?:^|\/)\.beads\/(?:config\.yaml|metadata\.json)$/.test(p) ||
    /\/opencode\/service\.json$/.test(p)
  );
}

export function redact(value) {
  let changed = false;
  const walk = (item, key = '') => {
    if (
      /^(?:password|passwd|token|secret|api[_-]?key|authorization|cookie|credential)$/i.test(key)
    ) {
      changed = true;
      return '[REDACTED]';
    }
    if (typeof item === 'string') {
      const result = item
        .replace(
          /\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{15,}|AKIA[A-Z0-9]{16})\b/g,
          '[REDACTED]',
        )
        .replace(/((?:Bearer|Basic)\s+)[A-Za-z0-9+/_=.-]{10,}/gi, '$1[REDACTED]')
        .replace(
          /((?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*)["']?[^\s"']{4,}/gi,
          '$1[REDACTED]',
        )
        .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/g, '$1[REDACTED]@');
      if (result !== item) changed = true;
      return result;
    }
    if (Array.isArray(item)) return item.map((v) => walk(v));
    if (item && typeof item === 'object')
      return Object.fromEntries(Object.entries(item).map(([k, v]) => [k, walk(v, k)]));
    return item;
  };
  return { value: walk(value), changed };
}

export function validateConfig(value) {
  if (!value || value.version !== VERSION || !['off', 'shadow', 'enforce'].includes(value.mode))
    throw new Error('Invalid approval mode/version');
  if (!value.model?.providerID || !value.model?.id || !value.model?.variant)
    throw new Error('Explicit classifier model and variant required');
  if (value.modelGrants && typeof value.modelGrants.enabled !== 'boolean')
    throw new Error('Model grant mode must be an explicit boolean');
  for (const name of ['skillRoots', 'protectedRoots']) {
    if (!Array.isArray(value[name]) || value[name].some((p) => !path.isAbsolute(p) || p === '/'))
      throw new Error(`Invalid ${name}`);
  }
  if (
    !path.isAbsolute(value.scratchRoot) ||
    value.scratchRoot === '/' ||
    value.scratchRoot === '/tmp' ||
    value.scratchRoot === '/private/tmp'
  )
    throw new Error('Dedicated scratch root required');
  if (!path.isAbsolute(value.auditRoot) || value.auditRoot === '/')
    throw new Error('Dedicated audit root required');
  if (!Number.isInteger(value.timeoutMs) || value.timeoutMs < 100 || value.timeoutMs > 60000)
    throw new Error('Invalid timeout');
  if (
    !Number.isInteger(value.maxRequestChars) ||
    value.maxRequestChars < 1000 ||
    value.maxRequestChars > 64000
  )
    throw new Error('Invalid input limit');
  return value;
}
