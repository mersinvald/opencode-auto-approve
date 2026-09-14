import path from 'node:path';
import { digest, within } from './policy.mjs';

export const isLegacyCommand = (r) => ['shell.opaque', 'native.opaque'].includes(r.operation);
export const grantDescriptor = (r) => ({
  operation: r.operation,
  target: r.target,
  targetType: r.targetType,
  ...(r.space ? { space: r.space } : {}),
});
export const grantLabel = (r) =>
  r.space
    ? `${r.repositoryName ?? r.space.repository.slice(0, 10)} · scratch · ${r.target}`
    : r.target;

export const modes = ['allow', 'ask', 'dynamic'];
export const modeLabels = { allow: 'Always allow', ask: 'Always ask', dynamic: 'Dynamic' };
export function grant(operation, target, targetType = 'file', extra = {}) {
  if (
    typeof operation !== 'string' ||
    !/^[a-zA-Z0-9_.:/-]{1,160}$/.test(operation) ||
    typeof target !== 'string' ||
    !target ||
    target.length > 8192 ||
    /[\0\r\n]/.test(target) ||
    !['file', 'directory', 'exact', 'any'].includes(targetType)
  )
    throw Error('Invalid grant');
  if (extra.space) {
    if (
      !/^[a-f0-9]{64}$/.test(extra.space.repository ?? '') ||
      extra.space.modifier !== 'scratch' ||
      Object.keys(extra.space).some((k) => !['repository', 'modifier'].includes(k))
    )
      throw Error('Invalid grant space');
    if (
      !['file', 'directory'].includes(targetType) ||
      path.isAbsolute(target) ||
      target.includes('\\') ||
      target.split('/').includes('..')
    )
      throw Error('Invalid relative grant target');
    target = path.posix.normalize(target);
  } else if (['file', 'directory'].includes(targetType)) {
    if (!path.isAbsolute(target)) throw Error('Grant path must be absolute');
    target = path.normalize(target);
  }
  return {
    ...extra,
    operation,
    target,
    targetType,
    id:
      'g_' +
      digest(grantDescriptor({ operation, target, targetType, space: extra.space })).slice(0, 24),
  };
}

export const ruleKey = (r) => digest(grantDescriptor(r));
export const selectedRulesHash = (rules, items) => {
  const keys = new Set(items.map(ruleKey));
  return digest(
    rules.filter((r) => keys.has(ruleKey(r))).sort((a, b) => ruleKey(a).localeCompare(ruleKey(b))),
  );
};
const operationMatches = (pattern, operation) =>
  pattern === '*' ||
  pattern === operation ||
  (pattern.endsWith('.*') && operation.startsWith(pattern.slice(0, -1)));
export function covers(rule, item) {
  if (isLegacyCommand(rule) || isLegacyCommand(item)) return false;
  if (rule.space) {
    if (
      !item.space ||
      rule.space.repository !== item.space.repository ||
      rule.space.modifier !== item.space.modifier
    )
      return false;
  } else if (item.space) {
    // Absolute legacy/global rules keep their exact physical boundary.
    if (!item.physicalTarget)
      return rule.targetType === 'any' && operationMatches(rule.operation, item.operation);
    item = { ...item, target: item.physicalTarget };
  }
  return (
    operationMatches(rule.operation, item.operation) &&
    (rule.targetType === 'any' ||
      (rule.targetType === 'directory' &&
        ['file', 'directory'].includes(item.targetType) &&
        (rule.space
          ? rule.target === '.' ||
            item.target === rule.target ||
            item.target.startsWith(rule.target + '/')
          : within(item.target, rule.target))) ||
      (rule.targetType !== 'directory' &&
        rule.target === item.target &&
        rule.targetType === item.targetType))
  );
}
const rank = (r) => [
  r.targetType === 'any' ? -1 : r.target.split('/').length,
  r.targetType === 'directory' ? 0 : 1,
  r.operation === '*' ? 0 : r.operation.endsWith('.*') ? 1 : 2,
  r.scope === 'project' ? 1 : 0,
  r.authority === 'user' ? 2 : r.authority === 'model' ? 1 : 0,
];
function compare(a, b, item) {
  const physical = (r) =>
    r.space && item?.binding?.root
      ? { ...r, target: path.resolve(item.binding.root, r.target) }
      : r;
  const x = rank(physical(a)),
    y = rank(physical(b));
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return y[i] - x[i];
  return (
    (b.updatedAt ?? '').localeCompare(a.updatedAt ?? '') || ruleKey(a).localeCompare(ruleKey(b))
  );
}
export function resolveGrant(item, rules) {
  const matches = rules.filter((r) => covers(r, item)).sort((a, b) => compare(a, b, item));
  const selected = matches.find((r) => r.locked && r.mode === 'ask') ?? matches[0];
  return { grant: item, mode: selected?.mode ?? 'dynamic', rule: selected ?? null };
}
export function resolveGrants(items, rules) {
  const entries = items.map((item) => resolveGrant(item, rules));
  return {
    entries,
    decision: entries.some((e) => e.mode === 'ask')
      ? 'ask'
      : entries.length && entries.every((e) => e.mode === 'allow')
        ? 'allow'
        : 'dynamic',
  };
}

// Structural ancestors are selectable scopes, not inferred permission rules.
export function grantTree(seen, rules) {
  const nodes = new Map();
  const add = (item) => {
    const key = ruleKey(item);
    if (!nodes.has(key)) nodes.set(key, { ...item, key, children: [], seen: false });
    return nodes.get(key);
  };
  for (const item of [...seen, ...rules].filter((r) => !isLegacyCommand(r))) {
    const node = add(item);
    node.seen ||= seen.some((s) => ruleKey(s) === node.key);
    if (['file', 'directory'].includes(item.targetType)) {
      let parent = path.dirname(item.target);
      while (true) {
        add({
          operation: item.operation,
          target: parent,
          targetType: 'directory',
          ...(item.space
            ? {
                space: item.space,
                repositoryName: item.repositoryName,
                ...(item.binding
                  ? {
                      binding: item.binding,
                      physicalTarget: path.resolve(item.binding.root, parent),
                    }
                  : {}),
              }
            : {}),
        });
        if (parent === (item.space ? '.' : '/')) break;
        parent = path.dirname(parent);
      }
    }
    add({ operation: item.operation, target: '*', targetType: 'any' });
  }
  const roots = [];
  for (const node of nodes.values()) {
    const parent =
      node.targetType === 'any'
        ? null
        : nodes.get(
            ruleKey({
              operation: node.operation,
              ...(node.space && node.target !== '.' ? { space: node.space } : {}),
              target:
                ['file', 'directory'].includes(node.targetType) &&
                node.target !== (node.space ? '.' : '/')
                  ? path.dirname(node.target)
                  : '*',
              targetType:
                ['file', 'directory'].includes(node.targetType) &&
                node.target !== (node.space ? '.' : '/')
                  ? 'directory'
                  : 'any',
            }),
          );
    const resolved = resolveGrant(node, rules);
    Object.assign(node, { mode: resolved.mode, rule: resolved.rule, parent: parent?.key ?? null });
    if (parent && parent !== node) parent.children.push(node);
    else roots.push(node);
  }
  const sort = (rows) => {
    rows.sort((a, b) => a.operation.localeCompare(b.operation) || a.target.localeCompare(b.target));
    rows.forEach((n) => sort(n.children));
  };
  sort(roots);
  return roots;
}
