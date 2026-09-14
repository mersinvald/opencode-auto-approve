import path from 'node:path';
import { digest, within } from './policy.mjs';

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
  if (['file', 'directory'].includes(targetType)) {
    if (!path.isAbsolute(target)) throw Error('Grant path must be absolute');
    target = path.normalize(target);
  }
  return {
    ...extra,
    operation,
    target,
    targetType,
    id: 'g_' + digest({ operation, target, targetType }).slice(0, 24),
  };
}

export const ruleKey = (r) =>
  digest({ operation: r.operation, target: r.target, targetType: r.targetType });
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
  return (
    operationMatches(rule.operation, item.operation) &&
    (rule.targetType === 'any' ||
      (rule.targetType === 'directory' &&
        ['file', 'directory'].includes(item.targetType) &&
        within(item.target, rule.target)) ||
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
function compare(a, b) {
  const x = rank(a),
    y = rank(b);
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return y[i] - x[i];
  return (
    (b.updatedAt ?? '').localeCompare(a.updatedAt ?? '') || ruleKey(a).localeCompare(ruleKey(b))
  );
}
export function resolveGrant(item, rules) {
  const matches = rules.filter((r) => covers(r, item)).sort(compare);
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
  for (const item of [...seen, ...rules]) {
    const node = add(item);
    node.seen ||= seen.some((s) => ruleKey(s) === node.key);
    if (['file', 'directory'].includes(item.targetType)) {
      let parent = path.dirname(item.target);
      while (true) {
        add({ operation: item.operation, target: parent, targetType: 'directory' });
        if (parent === '/') break;
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
              target:
                ['file', 'directory'].includes(node.targetType) && node.target !== '/'
                  ? path.dirname(node.target)
                  : '*',
              targetType:
                ['file', 'directory'].includes(node.targetType) && node.target !== '/'
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
