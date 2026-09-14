import { writeAudit } from './audit-storage.mjs';
export { writeAudit } from './audit-storage.mjs';
import { mkdir, lstat, realpath, open, readFile, readdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import { canonical, within, sensitivePath, digest, validateConfig } from './policy.mjs';
import { auditRecord, decisionReason } from './audit.mjs';
import { helperReferences, inlineHelperSources } from './shell-context.mjs';
import { permissionEvidence } from './native-permissions.mjs';
const scopeContext = (rootSessionID, users) => ({ rootSessionID, userHash: digest(users) });

class ReviewFailure extends Error {
  constructor(code, reason) {
    super(reason);
    this.approvalCode = code;
    this.approvalReason = reason;
  }
}

export function bounded(run, ms, parentSignal) {
  const controller = new AbortController();
  let timer, cancel;
  return Promise.race([
    Promise.resolve().then(() => {
      controller.signal.throwIfAborted();
      return run(controller.signal);
    }),
    new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new ReviewFailure('review_timeout', 'The approval review exceeded its time limit.'));
      }, ms);
    }),
    new Promise((_, reject) => {
      cancel = () => {
        controller.abort();
        reject(new ReviewFailure('review_cancelled', 'The pending review was cancelled.'));
      };
      if (parentSignal?.aborted) cancel();
      else parentSignal?.addEventListener('abort', cancel, { once: true });
    }),
  ]).finally(() => {
    clearTimeout(timer);
    parentSignal?.removeEventListener('abort', cancel);
  });
}

export async function scratchDirectory(root, sessionID) {
  // The parent must already exist. Never chmod an existing user directory.
  const parent = await realpath(path.dirname(root));
  if (path.join(parent, path.basename(root)) !== root)
    throw new Error('Scratch parent must be canonical');
  await mkdir(root, { mode: 0o700 }).catch((e) => {
    if (e.code !== 'EEXIST') throw e;
  });
  const check = async (p) => {
    const stat = await lstat(p);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      stat.uid !== process.getuid() ||
      stat.mode & 0o077
    )
      throw new Error('Unsafe scratch directory');
  };
  await check(root);
  const target = path.join(root, digest(sessionID).slice(0, 24));
  await mkdir(target, { mode: 0o700 }).catch((e) => {
    if (e.code !== 'EEXIST') throw e;
  });
  await check(target);
  return target;
}

export async function ancestorScratchDirectories(session, info, root, signal) {
  const safeDirectory = async (directory) => {
    const stat = await lstat(directory);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      stat.uid !== process.getuid() ||
      stat.mode & 0o077 ||
      (await realpath(directory)) !== directory
    )
      throw new Error('Unsafe ancestor scratch directory');
  };
  await safeDirectory(root);
  const directories = [],
    seen = new Set([info.id]);
  let parentID = info.parentID;
  for (let depth = 0; parentID && depth < 7; depth++) {
    if (seen.has(parentID)) throw new Error('Parent cycle');
    seen.add(parentID);
    const parent = await session.get({ sessionID: parentID }, { signal });
    if (parent.id !== parentID) throw new Error('Parent identity mismatch');
    const directory = path.join(root, digest(parent.id).slice(0, 24));
    try {
      await safeDirectory(directory);
      directories.push(directory);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    parentID = parent.parentID;
  }
  if (parentID) throw new Error('Incomplete parent chain');
  return directories;
}

export async function loadEvidence(session, sessionID, signal, maxChars = 96000, native) {
  const chain = [],
    seen = new Set();
  let id = sessionID;
  for (let depth = 0; id && depth < 8; depth++) {
    if (seen.has(id)) throw new Error('Parent cycle');
    seen.add(id);
    const info = await session.get({ sessionID: id }, { signal });
    if (info.id !== id) throw new Error('Session identity mismatch');
    const messages = await session.context({ sessionID: id }, { signal });
    chain.push({ info, messages });
    id = info.parentID;
  }
  if (id || !chain.length)
    throw new ReviewFailure(
      'user_context_incomplete',
      'The complete parent session chain is unavailable.',
    );
  const root = chain.at(-1);
  // A child's native "user" messages are often agent-authored launch briefs.
  const users = root.messages
    .filter((m) => m.type === 'user' && !m.metadata?.source && !m.metadata?.synthetic)
    .map((m) => ({ id: m.id, text: m.text }));
  if (!users.length || users.some((m) => typeof m.text !== 'string'))
    throw new Error('No eligible user instructions');
  // Never drop a restriction or a revoked authorization to fit a budget.
  if (JSON.stringify(users).length > maxChars)
    throw new ReviewFailure(
      'user_context_too_large',
      `Root user instructions exceed the ${maxChars}-character evidence budget.`,
    );
  const delegation = chain
    .slice(0, -1)
    .flatMap((c) =>
      c.messages
        .filter((m) => m.type === 'user')
        .map((m) => ({ sessionID: c.info.id, text: m.text })),
    )
    .slice(-4);
  if (JSON.stringify(delegation).length > maxChars)
    throw new ReviewFailure(
      'delegation_context_too_large',
      `Delegated instructions exceed the ${maxChars}-character evidence budget.`,
    );
  let nativePermissions;
  if (native) {
    try {
      nativePermissions = await permissionEvidence(
        chain,
        (projectID) => native.saved(projectID, signal),
        native.agentID ? await native.agent.get({ agentID: native.agentID }, { signal }) : null,
      );
      if (JSON.stringify(nativePermissions).length > maxChars)
        throw new Error('Permission evidence exceeds its budget');
    } catch {
      throw new ReviewFailure(
        'native_permissions_unavailable',
        'The review could not verify saved OpenCode permissions and current role rules.',
      );
    }
  }
  return {
    users,
    delegation,
    nativePermissions,
    context: scopeContext(root.info.id, users),
    scope: { directory: chain[0].info.location.directory },
    messages: chain[0].messages,
  };
}

async function readHelperSource(target, maxChars) {
  const { constants } = await import('node:fs');
  const file = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile())
      throw new ReviewFailure(
        'helper_source_unavailable',
        'The referenced helper is not a regular file.',
      );
    // UTF-8 uses at most four bytes per character. A bounded read also handles file growth.
    const maxBytes = maxChars * 4;
    if (stat.size > maxBytes)
      throw new ReviewFailure(
        'helper_source_too_large',
        `Helper source is ${stat.size} bytes and exceeds the ${maxChars}-character request budget.`,
      );
    const buffer = Buffer.alloc(maxBytes + 1);
    let used = 0;
    while (used < buffer.length) {
      const { bytesRead } = await file.read(buffer, used, buffer.length - used, used);
      if (!bytesRead) break;
      used += bytesRead;
    }
    if (used > maxBytes)
      throw new ReviewFailure(
        'helper_source_too_large',
        `Helper source exceeds the ${maxChars}-character request budget.`,
      );
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, used));
    } catch {
      throw new ReviewFailure(
        'helper_source_unavailable',
        'The referenced helper is not valid UTF-8 source.',
      );
    }
    if (text.length > maxChars)
      throw new ReviewFailure(
        'helper_source_too_large',
        `Helper source is ${text.length} characters and exceeds the ${maxChars}-character request budget.`,
      );
    return text;
  } finally {
    await file.close();
  }
}

export async function scriptEvidence(tool, scope, config, diagnostics = []) {
  const command = tool?.input?.command;
  if (typeof command !== 'string') return [];
  const scripts = [];
  const inline = inlineHelperSources(command);
  for (const name of helperReferences(command)) {
    const entry = {
      reference: name,
      cwd: tool.input.workdir || tool.input.cwd || scope.directory,
      language:
        {
          '.py': 'python',
          '.js': 'javascript',
          '.mjs': 'javascript',
          '.ts': 'typescript',
          '.sh': 'shell',
        }[path.extname(name)] ?? 'unknown',
      status: 'resolving',
      executed: false,
      analysis: 'source_snapshot_only',
    };
    diagnostics.push(entry);
    try {
      const target = await canonical(name, tool.input.workdir || tool.input.cwd || scope.directory);
      entry.path = target;
      if (sensitivePath(target, config.protectedRoots)) {
        entry.status = 'excluded_sensitive_path';
        continue;
      }
      if (scripts.some((script) => script.path === target && script.reference === name)) {
        entry.status = 'duplicate';
        continue;
      }
      if (scripts.length >= 3)
        throw new ReviewFailure(
          'helper_count_limit',
          'The request references more than three helper sources.',
        );
      const supplied = inline.filter((item) => item.reference === name);
      if (supplied.length > 1)
        throw new ReviewFailure(
          'helper_source_ambiguous',
          'The command defines this helper more than once. Its execution source needs manual review.',
        );
      if (supplied.length === 1) {
        const { text, ...location } = supplied[0];
        const before = command
          .split('\n')
          .slice(0, location.statementLine - 1)
          .join('\n');
        if (helperReferences(before).includes(name))
          throw new ReviewFailure(
            'helper_source_ambiguous',
            'The command references this helper before it defines the inline source. Its earlier contents need manual review.',
          );
        scripts.push({
          path: target,
          reference: name,
          cwd: tool.input.workdir || tool.input.cwd || scope.directory,
          source: 'inline',
          hash: digest(text),
          bodyInCommand: location,
        });
        Object.assign(entry, {
          status: 'captured',
          source: 'inline',
          hash: digest(text),
          chars: text.length,
          bytes: Buffer.byteLength(text),
          text,
          bodyInCommand: location,
        });
        continue;
      }
      let text;
      try {
        text = await readHelperSource(target, config.maxRequestChars);
      } catch (error) {
        if (['ENOENT', 'EACCES', 'EPERM'].includes(error.code)) {
          throw new ReviewFailure(
            'helper_source_unavailable',
            `Cannot read existing helper ${path.basename(target)} (${error.code}). Its source is unavailable for review.`,
          );
        }
        throw error;
      }
      scripts.push({
        path: target,
        reference: name,
        cwd: tool.input.workdir || tool.input.cwd || scope.directory,
        text,
        hash: digest(text),
      });
      Object.assign(entry, {
        status: 'captured',
        source: 'file',
        hash: digest(text),
        chars: text.length,
        bytes: Buffer.byteLength(text),
        text,
      });
    } catch (error) {
      Object.assign(entry, {
        status: 'failed',
        code: error.approvalCode ?? error.code ?? 'source_error',
        reason: error.approvalReason ?? 'Source capture failed',
      });
      throw error;
    }
  }
  return scripts;
}

export function sourceTool(event, captured, messages) {
  if (!event.source || event.source.type !== 'tool') return null;
  const key = `${event.sessionID}:${event.source.messageID}:${event.source.id}`;
  if (captured.has(key)) return captured.get(key);
  const message = messages.find((m) => m.id === event.source.messageID && m.type === 'assistant');
  const tool = message?.content?.find((p) => p.type === 'tool' && p.id === event.source.id);
  return tool?.state?.input && typeof tool.state.input === 'object'
    ? { name: tool.name, input: tool.state.input }
    : null;
}

export async function loadConfig(file) {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() || stat.mode & 0o022)
    throw new Error('Unsafe policy file');
  const config = validateConfig(JSON.parse(await readFile(file, 'utf8')));
  for (const name of ['skillRoots', 'protectedRoots'])
    config[name] = await Promise.all(config[name].map((p) => canonical(p, '/')));
  return config;
}
