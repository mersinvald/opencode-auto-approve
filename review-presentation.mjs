// Presentation only. Gate decisions, rule identities, and revalidation use the
// original evidence. No source or authority text is summarized here.
import path from 'node:path';

const key = (value) =>
  JSON.stringify(value, (_, v) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, v[k]]),
        )
      : v,
  );
const locationKeys = new Set(['commandIndex', 'line', 'column', 'endLine', 'endColumn']);

export function groupDiagnostics(items = []) {
  const groups = new Map();
  for (const item of items) {
    const detail = {},
      location = {};
    for (const [name, value] of Object.entries(item))
      (locationKeys.has(name) ? location : detail)[name] = value;
    const id = key(detail);
    if (!groups.has(id)) groups.set(id, { detail, first: item, count: 0, locations: new Map() });
    const group = groups.get(id),
      at = key(location);
    group.count++;
    if (!group.locations.has(at)) group.locations.set(at, { location, count: 0 });
    group.locations.get(at).count++;
  }
  return [...groups.values()].map(({ detail, first, count, locations }) =>
    count === 1
      ? first
      : {
          ...detail,
          occurrences: count,
          locations: [...locations.values()].map(({ location, count }) => ({
            ...location,
            ...(count > 1 ? { count } : {}),
          })),
        },
  );
}

function physicalRoot(item) {
  const { space, target, physicalTarget } = item;
  if (
    !space ||
    !physicalTarget ||
    !path.posix.isAbsolute(physicalTarget) ||
    path.posix.isAbsolute(target) ||
    target.split('/').includes('..')
  )
    return;
  const root =
    target === '.'
      ? physicalTarget
      : physicalTarget.endsWith('/' + target)
        ? physicalTarget.slice(0, -target.length - 1) || '/'
        : undefined;
  if (root && path.posix.join(root, target) === physicalTarget) return root;
}

export function compactResolvedGrants(items) {
  const groups = new Map();
  for (const item of items) {
    const { id, rule, target, physicalTarget, ...common } = item;
    const root = physicalRoot(item);
    if (root) common.physicalRoot = root;
    const identity = key(common);
    if (!groups.has(identity)) groups.set(identity, { ...common, targets: [] });
    groups.get(identity).targets.push({
      target,
      ...(physicalTarget && !root ? { physicalTarget } : {}),
    });
  }
  return [...groups.values()];
}

export function reviewPresentation(data) {
  const { grants = [], analysis = {}, ...rest } = data;
  const resolved = grants.filter((g) => g.mode === 'allow');
  return {
    reviewFocus: {
      pendingGrantIDs: grants.filter((g) => g.mode === 'dynamic').map((g) => g.id),
      parserCoverageIncomplete: analysis.complete !== true,
      resolvedGrantCount: resolved.length,
    },
    ...rest,
    analysis: {
      ...analysis,
      ...(analysis.unresolved ? { unresolved: groupDiagnostics(analysis.unresolved) } : {}),
      ...(analysis.pathResolutions
        ? {
            pathResolutions: [
              ...new Map(analysis.pathResolutions.map((p) => [key(p), p])).values(),
            ],
          }
        : {}),
    },
    grants: grants.filter((g) => g.mode !== 'allow'),
    resolvedGrants: compactResolvedGrants(resolved),
  };
}
