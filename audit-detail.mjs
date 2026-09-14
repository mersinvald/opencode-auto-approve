import { grantSnapshot } from './audit-grants.mjs';
import { createHash } from 'node:crypto';
import { mkdir, lstat, open, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { digest, redact } from './policy.mjs';

export const DETAIL_VERSION = 1;
const secretKey =
  /(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|credentials?|private[_-]?key)$/i;
const hash = (value) => createHash('sha256').update(value).digest('hex');

export function scrubAuditText(input) {
  let value = String(input);
  value = value.replace(
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    '[REDACTED PRIVATE KEY]',
  );
  // Match quoted Python/JSON assignments before generic token redaction.
  value = value.replace(
    /(["']?\b(?:[A-Za-z0-9_]*(?:password|passwd|passphrase|secret|token|api_key|apikey|access_key)|authorization|cookie|credentials?)["']?\s*[:=]\s*)(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;]+)/gi,
    (match, prefix) =>
      /authorization["']?\s*[:=]/i.test(prefix) && /["'](?:task|explicit|none)["']$/.test(match)
        ? match
        : prefix + '[REDACTED]',
  );
  value = value.replace(
    /(--(?:password|passwd|passphrase|token|api-key|secret)(?:=|\s+))(?:"[^"]*"|'[^']*'|\S+)/gi,
    '$1[REDACTED]',
  );
  value = value.replace(
    /([?&](?:token|api[_-]?key|secret|password|access_token)=)[^&#\s"']+/gi,
    '$1[REDACTED]',
  );
  value = String(redact(value).value);
  // Keep code whitespace. Escape controls which could spoof a log reader.
  return value.replace(
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,
    (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'),
  );
}

export function sanitizeAudit(value) {
  const redactions = [];
  const walk = (item, location) => {
    if (typeof item === 'string') {
      const clean = scrubAuditText(item);
      if (clean !== item) redactions.push(location);
      return clean;
    }
    if (Array.isArray(item)) return item.map((v, i) => walk(v, location + '[' + i + ']'));
    if (item && typeof item === 'object') {
      return Object.fromEntries(
        Object.entries(item).map(([key, child]) => {
          const p = location + '.' + key;
          // "authorization" is also a public decision-schema enum.
          const decisionEnum =
            key === 'authorization' && ['task', 'explicit', 'none'].includes(child);
          if (secretKey.test(key) && !decisionEnum) {
            redactions.push(p);
            return [key, '[REDACTED]'];
          }
          return [scrubAuditText(key), walk(child, p)];
        }),
      );
    }
    return typeof item === 'number' && !Number.isFinite(item) ? null : item;
  };
  const data = walk(value, '$');
  return {
    version: DETAIL_VERSION,
    data,
    capture: {
      hashFormat: 'sha256-json',
      redacted: redactions.length > 0,
      redactions,
      truncated: false,
      omissions: [],
      originalHash: digest(value),
      storedHash: digest(data),
    },
  };
}

export function detailPayload({
  event,
  request,
  scope,
  config,
  result,
  modelDecision,
  modelResponse,
  diagnostics,
}) {
  const { helpers, ...diagnosticFields } = diagnostics ?? {};
  return sanitizeAudit({
    schema: 'opencode.approval.detail',
    grants: grantSnapshot(diagnostics?.static),
    capturedAt: new Date().toISOString(),
    source: {
      sessionID: event.sessionID,
      agent: event.agent,
      toolCall: event.source,
      action: event.action,
    },
    request: {
      action: request.action,
      effect: request.effect,
      resources: request.resources,
      tool: request.tool,
      directory: request.directory,
      scratch: request.scratch,
      originalHash: digest(request.tool?.input ?? request),
    },
    helpers: helpers ?? request.scripts ?? [],
    scope,
    decision: {
      effect: result.effect,
      code: result.code,
      reason: result.reason,
      stage: result.stage,
      modelDecision,
      modelResponse,
    },
    diagnostics: diagnosticFields,
    policy: config && {
      version: config.version,
      hash: digest(config),
      mode: config.mode,
      model: config.model,
      protectedRoots: config.protectedRoots,
      skillRoots: config.skillRoots,
      staticShell: config.staticShell,
      staticPython: config.staticPython,
    },
    staticAnalysis: result.staticAnalysis ?? request.staticAnalysis,
  });
}

export function extendDetail(payload, lifecycle) {
  if (!payload) return undefined;
  // Keep the final native outcome and the earlier capture provenance.
  const { lifecycle: previousLifecycle, ...data } = payload.data;
  const result = sanitizeAudit({ lifecycle, ...data });
  result.capture.redacted ||= payload.capture?.redacted ?? false;
  result.capture.truncated ||= payload.capture?.truncated ?? false;
  result.capture.previous = payload.capture;
  return result;
}

async function privateDirectory(directory) {
  await mkdir(directory, { mode: 0o700 }).catch((e) => {
    if (e.code !== 'EEXIST') throw e;
  });
  const st = await lstat(directory);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || st.mode & 0o077)
    throw Error('unsafe_detail_directory');
}
// Optional verbose capture must not create a new permission failure mode.
// The compact audit append remains mandatory for automatic approval.
export async function writeDetail(root, payload, day) {
  try {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) throw Error('invalid_detail_date');
    const base = path.join(root, 'details'),
      directory = path.join(base, day);
    await privateDirectory(base);
    await privateDirectory(directory);
    const serialized = JSON.stringify(payload, null, 2) + '\n';
    const sha256 = hash(serialized),
      name = sha256 + '.json',
      filePath = path.join(directory, name);
    let file;
    try {
      file = await open(
        filePath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const prior = await readDetail(root, { path: path.join('details', day, name), sha256 });
      if (!prior) throw Error('detail_collision');
    }
    if (file) {
      try {
        await file.writeFile(serialized);
        await file.sync();
      } catch (error) {
        await unlink(filePath).catch(() => {});
        throw error;
      } finally {
        await file.close();
      }
    }
    return {
      status: 'stored',
      path: path.join('details', day, name),
      sha256,
      bytes: Buffer.byteLength(serialized),
      redacted: payload.capture?.redacted ?? false,
      truncated: payload.capture?.truncated ?? false,
    };
  } catch (error) {
    return {
      status: 'unavailable',
      code: /^[a-z_]+$/.test(error.message) ? error.message : 'detail_write_failed',
    };
  }
}

export async function readDetail(root, reference) {
  if (
    !/^details\/\d{4}-\d{2}-\d{2}\/[a-f0-9]{64}\.json$/.test(reference?.path) ||
    path.basename(reference.path) !== reference.sha256 + '.json'
  )
    throw Error('Invalid audit detail reference');
  for (const directory of [
    root,
    path.join(root, 'details'),
    path.join(root, path.dirname(reference.path)),
  ]) {
    const st = await lstat(directory);
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || st.mode & 0o077)
      throw Error('Unsafe audit detail directory');
  }
  const file = await open(
    path.join(root, reference.path),
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const st = await file.stat();
    if (!st.isFile() || st.uid !== process.getuid() || st.mode & 0o077)
      throw Error('Unsafe audit detail file');
    const text = await file.readFile();
    if (hash(text) !== reference.sha256) throw Error('Audit detail hash mismatch');
    return JSON.parse(text.toString('utf8'));
  } finally {
    await file.close();
  }
}
