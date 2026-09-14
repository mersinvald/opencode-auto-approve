import { grantDescriptor, resolveGrants, isLegacyCommand } from './grant-rules.mjs';

export const ruleSnapshot = (rule) =>
  rule && {
    ...grantDescriptor(rule),
    repositoryName: rule.repositoryName,
    mode: rule.mode,
    scope: rule.scope,
    authority: rule.authority,
    source: rule.provenance?.source,
  };
export const entrySnapshots = (entries) =>
  (Array.isArray(entries) ? entries : [])
    .filter((e) => e && e.grant && typeof e.grant === 'object' && !isLegacyCommand(e.grant))
    .map(({ grant, mode, rule }) => ({
      grant: {
        ...grantDescriptor(grant),
        id: grant.id,
        repositoryName: grant.repositoryName,
        physicalTarget: grant.physicalTarget,
        binding: grant.binding,
        ...(grant.locations?.length ? { locations: grant.locations } : {}),
      },
      mode,
      rule: ruleSnapshot(rule),
    }));

export function grantSnapshot(checked) {
  if (!checked?.analysis || typeof checked.analysis !== 'object') return undefined;
  const a = checked.analysis;
  return {
    complete: a.complete,
    reason: a.reason,
    decision: checked.decision,
    restriction: checked.reason,
    entries: entrySnapshots(
      checked.resolution?.entries ??
        (Array.isArray(a.grants) ? a.grants : []).map((grant) => ({ grant })),
    ),
    unresolved: (Array.isArray(a.unresolved)
      ? a.unresolved
      : a.complete === false
        ? [{ reason: a.reason }]
        : []
    )
      .filter((u) => u && typeof u === 'object')
      .map((u) => ({
        ...u,
        command: Number.isInteger(u.commandIndex) ? a.commands?.[u.commandIndex] : undefined,
      })),
  };
}

// Describe the actual store transaction, rather than the model's proposal.
export function savedGrantSnapshot(items, global, before, after) {
  return {
    before: entrySnapshots(resolveGrants(items, [...global, ...before]).entries),
    after: entrySnapshots(resolveGrants(items, [...global, ...after]).entries),
  };
}
