import { createHash } from 'node:crypto';
import { mkdir, lstat, open, readdir, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { digest, redact } from './policy.mjs';

export const DETAIL_VERSION = 1;
export const DETAIL_MAX_BYTES = 512 * 1024;
const dayBudget = 128 * 1024 * 1024;
const secretKey =
  /(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|credentials?|private[_-]?key)$/i;
const budgets = new Map();
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

export function sanitizeAudit(value, { maxChars = 180000, maxString = 65536 } = {}) {
  const redactions = [],
    omissions = [];
  let remaining = maxChars,
    nodes = 0;
  const walk = (item, location, depth) => {
    if (++nodes > 16000 || depth > 40 || remaining <= 0) {
      if (omissions.length < 100) omissions.push({ path: location, reason: 'record_budget' });
      return '[OMITTED: audit budget]';
    }
    if (typeof item === 'string') {
      const clean = scrubAuditText(item);
      if (clean !== item && redactions.length < 100) redactions.push(location);
      const limit = Math.min(maxString, remaining),
        text = clean.slice(0, limit);
      remaining -= text.length;
      if (text.length !== clean.length && omissions.length < 100)
        omissions.push({
          path: location,
          reason: 'text_budget',
          originalChars: item.length,
          sanitizedChars: clean.length,
          storedChars: text.length,
        });
      return text;
    }
    if (Array.isArray(item)) {
      if (item.length > 256 && omissions.length < 100)
        omissions.push({ path: location, reason: 'array_budget', originalItems: item.length });
      return item.slice(0, 256).map((v, i) => walk(v, location + '[' + i + ']', depth + 1));
    }
    if (item && typeof item === 'object') {
      const entries = Object.entries(item);
      if (entries.length > 256 && omissions.length < 100)
        omissions.push({ path: location, reason: 'object_budget' });
      return Object.fromEntries(
        entries.slice(0, 256).map(([key, child]) => {
          remaining -= key.length;
          const p = location + '.' + key;
          // "authorization" is also a public decision-schema enum.
          const decisionEnum =
            key === 'authorization' && ['task', 'explicit', 'none'].includes(child);
          if (secretKey.test(key) && !decisionEnum) {
            if (redactions.length < 100) redactions.push(p);
            return [key, '[REDACTED]'];
          }
          return [scrubAuditText(key), walk(child, p, depth + 1)];
        }),
      );
    }
    return typeof item === 'number' && !Number.isFinite(item) ? null : item;
  };
  const data = walk(value, '$', 0);
  return {
    version: DETAIL_VERSION,
    data,
    capture: {
      hashFormat: 'sha256-json',
      redacted: redactions.length > 0,
      redactions,
      truncated: omissions.length > 0,
      omissions,
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
    },
    staticAnalysis: result.staticAnalysis ?? request.staticAnalysis,
  });
}

export function extendDetail(payload, lifecycle) {
  if (!payload) return undefined;
  // Keep the final native outcome even if a large source snapshot exhausts the budget.
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
async function usage(directory) {
  const cached = budgets.get(directory);
  if (cached && Date.now() - cached.time < 60000) return cached;
  let bytes = 0;
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (/^[a-f0-9]{64}\.json$/.test(entry.name) && entry.isFile())
      bytes += (await lstat(path.join(directory, entry.name))).size;
  }
  const value = { time: Date.now(), bytes };
  budgets.set(directory, value);
  return value;
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
    let serialized = JSON.stringify(payload, null, 2) + '\n';
    if (Buffer.byteLength(serialized) > DETAIL_MAX_BYTES) {
      const previous = payload.capture;
      payload = sanitizeAudit(payload.data, { maxChars: 24000, maxString: 8000 });
      payload.capture.redacted ||= previous?.redacted ?? false;
      payload.capture.previous = previous;
      payload.capture.truncated = true;
      payload.capture.omissions.push({ path: '$', reason: 'serialized_byte_budget' });
      serialized = JSON.stringify(payload, null, 2) + '\n';
    }
    if (Buffer.byteLength(serialized) > DETAIL_MAX_BYTES) throw Error('detail_size_limit');
    const sha256 = hash(serialized),
      name = sha256 + '.json',
      filePath = path.join(directory, name);
    const current = await usage(directory);
    if (current.bytes + Buffer.byteLength(serialized) > dayBudget)
      throw Error('detail_daily_budget');
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
      current.bytes += Buffer.byteLength(serialized);
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
    if (
      !st.isFile() ||
      st.uid !== process.getuid() ||
      st.mode & 0o077 ||
      st.size > DETAIL_MAX_BYTES
    )
      throw Error('Unsafe audit detail file');
    const buffer = Buffer.alloc(DETAIL_MAX_BYTES + 1),
      { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    const text = buffer.subarray(0, bytesRead);
    if (hash(text) !== reference.sha256) throw Error('Audit detail hash mismatch');
    return JSON.parse(text.toString('utf8'));
  } finally {
    await file.close();
  }
}

export async function pruneDetails(root, cutoff) {
  const base = path.join(root, 'details');
  try {
    const st = await lstat(base);
    if (!st.isDirectory() || st.isSymbolicLink()) return;
    for (const day of await readdir(base, { withFileTypes: true })) {
      if (
        !day.isDirectory() ||
        !/^\d{4}-\d{2}-\d{2}$/.test(day.name) ||
        Date.parse(day.name) >= cutoff
      )
        continue;
      const directory = path.join(base, day.name);
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        if (entry.isFile() && /^[a-f0-9]{64}\.json$/.test(entry.name))
          await unlink(path.join(directory, entry.name));
      }
      budgets.delete(directory);
    }
  } catch {
    /* Retention failure cannot change a permission decision. */
  }
}
