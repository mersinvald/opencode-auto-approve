# Decision flow

1. Capture the native request, tool input, actual working directory, and shell runtime.
2. Collect user instructions, delegation context, existing permissions, and bounded helper source.
3. Convert the action into operation and target grants.
4. Resolve global and project rules for each grant.
5. Apply a complete static allow or present an explicit Always ask decision.
6. For Dynamic grants, keep the native dialog open and request model review.
7. Validate the response and check whether the action, rules, source, or instructions changed.
8. Apply an automatic reply only if the native request is still pending.
9. Save selected rules only after the native service confirms the automatic reply.

The model selects `allow_once`, `escalate_once`, or `allow_always`. Remembered targets must come from the supplied candidate list. Unknown effects remain per-request analysis context and never become saved permissions.

Repeated consequential operations require explicit user instructions. Routine local scopes can derive from the current task. The model interprets this authorization boundary. Schema validation alone cannot prove that its interpretation is correct.

The background queue retries transient failures with bounded attempts and backoff. Malformed responses receive schema feedback. Exhausted failures leave the native approval request for the user.

The audit viewer checks pending permissions before it sends a notification. It notifies after escalation, terminal review failure, or five minutes without a decision. Native operating-system notifications currently target macOS.

## Module map

| Modules                                                | Responsibility                                              |
| ------------------------------------------------------ | ----------------------------------------------------------- |
| `index.mjs`, `review-context.mjs`                      | OpenCode hooks, context, lifecycle, and race checks         |
| `action-grants.mjs`, `shell-*`, `sqlite-read.mjs`      | Static action and shell analysis                            |
| `shell-parser/`                                        | Syntax-only Go adapter for mvdan/sh                         |
| `grant-gate.mjs`, `grant-rules.mjs`, `grant-space.mjs` | Operation rules, scope precedence, and native restrictions  |
| `grant-store.mjs`, `native-permissions.mjs`            | Private project storage and permission migration            |
| `grant-decision.mjs`, `grant-review.mjs`               | Model contract and reviewed decision validation             |
| `structured-classifier.mjs`                            | Bounded Chat Completions transport and response decoding    |
| `async-review.mjs`, `native-transport.mjs`             | Background review and native pending-request recovery       |
| `audit*.mjs`, `grant-tree-tui.mjs`                     | Detailed records, terminal output, and project grant editor |
| `approval-notifications.mjs`                           | Notification decisions and macOS delivery                   |

## Grant identity and worktrees

A grant identifies an operation, target, and target type. Verified linked worktrees also carry `space.repository` and `space.modifier: scratch`. Their targets are relative to the checkout root.

The repository identity includes its canonical Git common directory and filesystem identity. Linkage validation checks the worktree marker, common directory, and reverse link. The main checkout receives no scratch identity.

Rules remain project-scoped. One project can contain separate identities for several repositories. Physical paths and linkage proofs remain in request evidence and revalidation fingerprints. They do not form reusable rule keys.

Absolute legacy and global rules match the current physical path. Migration does not broaden them to future worktrees.

## Static analysis limits

Known native reads and edits map directly to grants. Unsupported native actions, shell syntax, flags, or runtime settings mark analysis incomplete. The gate retains known effects and reports the unresolved analysis in the audit.

An effective Always ask rule takes precedence, including for a known effect within an incomplete analysis. Static approval requires complete analysis and an allow rule for every effect. Otherwise, the model reviews the full command and available helper sources. It can save supplied atomic candidates, but it cannot save approval for unresolved command syntax.

The parser can normalize literal variables, bounded arrays, paths, filters, and limited metadata substitutions. It does not execute the proposed command. Python helpers go to the model as bounded source context. General Python static analysis is not implemented.

Repository, secret, policy, Beads, and test operations remain distinct. Reading `AGENTS.md` is allowed by default. A symlink to secret material still requires a secret read grant.

This system does not enforce permissions at the operating-system level. Files or environment state can change between review and actual execution.

## Storage migration

Version 3 stores no legacy command-specific approvals or observations. The first read backs up each version 2 store before migration. Backups remain beside the store with a `.backup` suffix and owner-only permissions.

Bounded file, Beads, and test rules keep their scope and provenance. Verified worktree observations merge by repository and relative target. Native interpreter wildcards create no imported grant. Without complete static analysis, those requests remain subject to model review.

Legacy command-specific Always ask rules cannot safely become atomic rules automatically. Such a restriction retains an escalation guard (`legacyShellAsk` or `legacyNativeAsk`) until an administrator replaces it with explicit atomic restrictions. Remove that guard only after restoring the intended restrictions. Normal allow and Dynamic migrations need no manual step.

The model receives the current request, authority context, relevant atomic permissions, and candidate scopes. Unrelated grant history and repeated native permission records remain outside its prompt. Detailed analysis remains available in the private audit.
