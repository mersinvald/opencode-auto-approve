import { open, mkdir, lstat, realpath, rename, unlink, readdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { digest } from './policy.mjs';
import { grant, modes, ruleKey } from './grant-rules.mjs';

export const ruleDirectory = (policyFile) => path.join(path.dirname(policyFile), 'approval-rules');
const validID = (id) => typeof id === 'string' && /^[a-zA-Z0-9_-]{1,180}$/.test(id);
const empty = (projectID) => ({
  version: 2,
  projectID,
  revision: 0,
  rules: [],
  seen: [],
  imported: [],
});
function validateRule(item) {
  if (
    typeof item?.operation !== 'string' ||
    !/^([a-zA-Z0-9_.:/-]{1,158}\.\*|\*|[a-zA-Z0-9_.:/-]{1,160})$/.test(item.operation)
  )
    throw Error('Invalid rule operation');
  grant(item.operation.replace(/\*/g, 'all'), item.target, item.targetType);
}
async function readJSON(file) {
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await fd.stat();
    if (
      !stat.isFile() ||
      stat.uid !== process.getuid() ||
      stat.mode & 0o077 ||
      stat.size > 4 * 1024 * 1024
    )
      throw Error('Unsafe grant store');
    return JSON.parse(await fd.readFile('utf8'));
  } finally {
    await fd.close();
  }
}
export function createRuleStore(policyFile) {
  const directory = ruleDirectory(policyFile);
  const filename = (id) => {
    if (!validID(id)) throw Error('Invalid project');
    return path.join(directory, id + '.json');
  };
  async function ensure() {
    await mkdir(directory, { mode: 0o700 }).catch((e) => {
      if (e.code !== 'EEXIST') throw e;
    });
    const stat = await lstat(directory);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      stat.uid !== process.getuid() ||
      stat.mode & 0o077 ||
      (await realpath(directory)) !== directory
    )
      throw Error('Unsafe grant directory');
  }
  async function read(projectID) {
    await ensure();
    let state;
    try {
      state = await readJSON(filename(projectID));
    } catch (e) {
      if (e.code === 'ENOENT') return empty(projectID);
      throw e;
    }
    if (
      state.version !== 2 ||
      state.projectID !== projectID ||
      !Number.isInteger(state.revision) ||
      !Array.isArray(state.rules) ||
      !Array.isArray(state.seen) ||
      !Array.isArray(state.imported)
    )
      throw Error('Invalid grant store');
    for (const r of state.rules) {
      if (!modes.includes(r.mode) || !['user', 'model', 'import'].includes(r.authority))
        throw Error('Invalid grant rule');
      validateRule(r);
    }
    return state;
  }
  async function update(projectID, change) {
    await ensure();
    const dest = filename(projectID),
      lock = dest + '.lock';
    let fd;
    const start = Date.now();
    while (!fd) {
      try {
        fd = await open(
          lock,
          constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
          0o600,
        );
      } catch (e) {
        if (e.code !== 'EEXIST' || Date.now() - start > 2500) throw Error('Grant store is busy');
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
    const tmp = dest + '.' + randomUUID() + '.tmp';
    try {
      const state = await read(projectID),
        before = digest(state);
      await change(state);
      if (before === digest(state)) return state;
      state.revision++;
      const output = await open(
        tmp,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
        0o600,
      );
      try {
        await output.writeFile(JSON.stringify(state) + '\n');
        await output.sync();
      } finally {
        await output.close();
      }
      await rename(tmp, dest);
      return state;
    } finally {
      await fd.close();
      await unlink(tmp).catch(() => {});
      await unlink(lock);
    }
  }
  return {
    directory,
    read,
    update,
    async observe(projectID, items, source) {
      return update(projectID, (state) => {
        const now = new Date().toISOString();
        for (const item of items) {
          const previous = state.seen.find((s) => ruleKey(s) === ruleKey(item));
          if (previous)
            Object.assign(previous, { lastSeen: now, count: previous.count + 1, source });
          else state.seen.push({ ...item, firstSeen: now, lastSeen: now, count: 1, source });
        }
        if (state.seen.length > 4000) state.seen = state.seen.slice(-4000);
      });
    },
    async set(projectID, item, mode, authority = 'user', provenance = {}, expectedRules) {
      if (!modes.includes(mode) || !['user', 'model'].includes(authority))
        throw Error('Invalid rule decision');
      validateRule(item);
      return update(projectID, (state) => {
        if (expectedRules !== undefined && digest(state.rules) !== expectedRules)
          throw Error('Project rules changed');
        const key = ruleKey(item);
        state.rules = state.rules.filter((r) => ruleKey(r) !== key);
        state.rules.push({
          operation: item.operation,
          target: item.target,
          targetType: item.targetType,
          mode,
          scope: 'project',
          authority,
          provenance,
          updatedAt: new Date().toISOString(),
        });
      });
    },
    async import(projectID, native, legacy = []) {
      return update(projectID, (state) => {
        const add = (source, item, mode, original) => {
          const key = source + ':' + ruleKey(item);
          if (state.imported.includes(key)) return;
          state.imported.push(key);
          if (!state.rules.some((r) => ruleKey(r) === ruleKey(item)))
            state.rules.push({
              ...item,
              mode,
              scope: 'project',
              authority: 'import',
              provenance: { source, original },
              updatedAt: new Date().toISOString(),
            });
        };
        for (const row of native.filter((r) => r.projectID === projectID)) {
          const target = row.resource.replace(/\/\*$/, '');
          if (row.action === 'read' && row.resource === '*') {
            // Native read approval covers normal file contents and directory
            // listings. Secret and policy operations retain separate grants.
            for (const operation of ['files.read', 'files.list'])
              add(row.id, grant(operation, '*', 'any'), 'allow', row);
            continue;
          }
          if (row.action === 'shell') {
            add(
              row.id,
              { operation: 'shell.opaque', target: row.resource, targetType: 'exact' },
              'dynamic',
              row,
            );
            continue;
          }
          if (!path.isAbsolute(target) || /[*?\[\]{}]/.test(target)) continue;
          const type =
            row.resource.endsWith('/*') || row.action === 'external_directory'
              ? 'directory'
              : 'file';
          const ops =
            row.action === 'external_directory'
              ? ['files.access', 'files.read', 'files.list', 'git.read']
              : row.action === 'edit'
                ? ['files.read', 'files.write']
                : row.action === 'read'
                  ? ['files.read', 'files.list', 'git.read']
                  : [];
          for (const operation of ops) add(row.id, grant(operation, target, type), 'allow', row);
          if (
            row.action === 'external_directory' &&
            native.some(
              (r) => r.projectID === projectID && r.action === 'edit' && r.resource === '*',
            )
          )
            add(row.id, grant('files.write', target, type), 'allow', row);
        }
        for (const row of legacy.filter((r) => r.projectID === projectID)) {
          const operations =
            {
              'files.read': ['files.read', 'files.list', 'git.read', 'files.access'],
              'files.edit': ['files.read', 'files.list', 'files.write', 'git.read', 'files.access'],
              'beads.read': ['beads.read'],
              'beads.update': ['beads.read', 'beads.update'],
              'beads.manage': ['beads.read', 'beads.update', 'beads.manage'],
              'tests.run': ['tests.run'],
            }[row.category] ?? [];
          for (const operation of operations)
            add(
              row.id,
              grant(operation, row.target, row.targetType),
              row.revokedAt
                ? 'ask'
                : row.invalid || row.authority === 'model-context'
                  ? 'dynamic'
                  : 'allow',
              row,
            );
        }
      });
    },
  };
}

export async function legacyGrants(policyFile) {
  const directory = path.join(path.dirname(policyFile), 'approval-grants');
  let names;
  try {
    names = await readdir(directory);
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
  return Promise.all(
    names
      .filter((n) => /^grant_[a-f0-9-]+\.json$/.test(n))
      .map((n) => readJSON(path.join(directory, n))),
  );
}
