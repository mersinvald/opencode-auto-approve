import { worktreeGrant } from './grant-space.mjs';
import path from 'node:path';
import { lstat } from 'node:fs/promises';
import { grant, resolveGrants, covers, grantDescriptor } from './grant-rules.mjs';
import { extractAction } from './action-grants.mjs';
import { digest, within, secretPath, policyPath } from './policy.mjs';
import { repositoryScope } from './repository-scope.mjs';

const controlActions = [
  'execute',
  'skill',
  'subagent',
  'question',
  'ask_coordinator',
  'answer_worker',
  'steer_worker',
  'wait_worker',
  'batch_status',
  'task_status',
  'task_result',
  'task_cancel',
  'wait_for_user',
  'approval_scratch',
];
export function globalRules(config, scope) {
  const result = [],
    add = (operation, target, targetType = 'directory') =>
      result.push({
        operation,
        target,
        targetType,
        mode: 'allow',
        scope: 'global',
        authority: 'config',
        provenance: { source: 'global defaults' },
      });
  add('instructions.read', '*', 'any');
  for (const root of [
    scope.directory,
    scope.scratch,
    ...(scope.readableAncestorScratch ?? []),
    ...config.skillRoots,
  ].filter(Boolean)) {
    for (const op of ['files.access', 'files.read', 'files.list', 'git.read', 'shell.stream'])
      add(op, root);
  }
  if (scope.scratch) {
    add('files.write', scope.scratch);
    add('files.delete', scope.scratch);
  }
  for (const helper of config.staticShell?.helpers ?? [])
    add('tools.lint', helper.realpath, 'file');
  for (const action of controlActions) add('native.' + action, '*', 'any');
  return [
    ...result,
    ...(config.grantRules ?? []).map((r) => ({ ...r, scope: 'global', authority: 'config' })),
  ];
}
function matches(pattern, value) {
  if (typeof pattern !== 'string' || /[\[\]{}\\]/.test(pattern)) return true;
  return new RegExp(
    '^' +
      pattern
        .split(/([*?])/)
        .map((s) => (s === '*' ? '.*' : s === '?' ? '.' : s.replace(/[.+^$()|]/g, '\\$&')))
        .join('') +
      '$',
    's',
  ).test(value);
}
export function nativeRestriction(request, analysis, permissions, scope, config) {
  if (request.effect === 'deny') return 'Native deny rule';
  const writes = analysis.grants.some((g) =>
    [
      'files.write',
      'policy.write',
      'secrets.write',
      'files.delete',
      'policy.delete',
      'secrets.delete',
      'beads.update',
      'beads.manage',
    ].includes(g.operation),
  );
  if (scope.readOnly && writes) return 'This role may not write project state';
  if (
    analysis.grants.some((g) => ['beads.update', 'beads.manage'].includes(g.operation)) &&
    !(config.staticShell?.beadsWriters ?? ['orchestrator']).includes(scope.agent)
  )
    return 'Only Beads writer roles may update issues';
  const rules = [
    ...(permissions?.sessions ?? []).flatMap((s) => s.rules ?? []),
    ...(permissions?.agent?.rules ?? []),
  ];
  for (const r of rules.filter((r) => r.effect === 'deny')) {
    if ([r.action, '*'].includes(request.action) || r.action === '*') {
      if (request.resources.some((x) => matches(r.resource, x))) return 'Native deny rule';
    }
    for (const item of analysis.grants) {
      const actions =
        /\.(write|delete)$/.test(item.operation) ||
        item.operation === 'beads.update' ||
        item.operation === 'beads.manage'
          ? ['*', 'edit', 'external_directory']
          : ['*', 'read', 'external_directory'];
      if (actions.includes(r.action) && matches(r.resource, item.physicalTarget ?? item.target))
        return 'Native deny rule';
    }
    if (
      ['*', 'shell'].includes(r.action) &&
      analysis.commands.some((c) => matches(r.resource, c.argv.join(' ')))
    )
      return 'Native deny rule';
  }
  return null;
}
export async function gate(request, { scope, config, runtime, permissions, state, signal }) {
  const analysis = await extractAction(request, { scope, config, runtime, permissions, signal });
  analysis.grants = await Promise.all(analysis.grants.map(worktreeGrant));
  const rules = [...globalRules(config, scope), ...state.rules];
  const resolution = resolveGrants(analysis.grants, rules);
  const restricted =
    nativeRestriction(request, analysis, permissions, scope, config) ??
    (state.legacyNativeAsk?.some((action) => action === '*' || action === request.action)
      ? 'A legacy native Always ask rule requires migration to atomic permissions.'
      : null);
  const candidates = new Map();
  for (const { grant: item, mode } of resolution.entries) {
    if (mode !== 'dynamic' || item.rememberable === false) continue;
    candidates.set(item.id, item);
    if (item.space) {
      for (
        let p = item.targetType === 'file' ? path.dirname(item.target) : item.target;
        ;
        p = path.dirname(p)
      ) {
        const broader = grant(item.operation, p, 'directory', {
          space: item.space,
          repositoryName: item.repositoryName,
        });
        const physical = path.resolve(item.binding.root, p);
        if (
          !secretPath(physical) &&
          !policyPath(physical, [...config.protectedRoots, ...config.skillRoots]) &&
          !resolution.entries.some((e) => e.mode === 'ask' && covers(broader, e.grant))
        )
          candidates.set(broader.id, broader);
        if (p === '.') break;
      }
    } else if (['file', 'directory'].includes(item.targetType)) {
      const parent = item.targetType === 'file' ? path.dirname(item.target) : item.target;
      let existing = parent;
      while (
        existing !== '/' &&
        !(await lstat(existing).catch((e) => {
          if (e.code !== 'ENOENT') throw e;
        }))
      )
        existing = path.dirname(existing);
      const repo = await repositoryScope(existing).catch(() => null);
      const parents = [parent];
      for (
        let p = parent;
        repo?.root && p !== repo.root && within(p, repo.root) && parents.length < 12;

      ) {
        p = path.dirname(p);
        parents.push(p);
      }
      for (const target of parents) {
        if (
          target === '/' ||
          target === process.env.HOME ||
          secretPath(target) ||
          policyPath(target, config.protectedRoots)
        )
          continue;
        const broader = grant(item.operation, target, 'directory');
        if (resolution.entries.some((e) => e.mode === 'ask' && covers(broader, e.grant))) continue;
        candidates.set(broader.id, broader);
      }
    }
  }
  return {
    analysis,
    resolution,
    candidates: [...candidates.values()],
    rulesHash: digest(state.rules),
    decision:
      restricted ||
      resolution.decision === 'ask' ||
      (state.legacyShellAsk && request.action === 'shell')
        ? 'ask'
        : analysis.complete
          ? resolution.decision
          : 'dynamic',
    reason:
      restricted ??
      (state.legacyShellAsk && request.action === 'shell'
        ? 'A legacy command-specific Always ask rule requires migration to atomic permissions.'
        : null),
    fingerprint: digest({
      analysis,
      restricted,
      legacyShellAsk: !!state.legacyShellAsk,
      resolution: resolution.entries.map((e) => ({
        id: e.grant.id,
        mode: e.mode,
        rule: e.rule && {
          ...grantDescriptor(e.rule),
          mode: e.rule.mode,
        },
      })),
    }),
  };
}
