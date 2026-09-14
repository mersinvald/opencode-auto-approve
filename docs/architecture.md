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

The shell parser can normalize literal variables, bounded arrays, paths, filters, and limited metadata substitutions. It does not execute the proposed command.

A missing pytest target requires model review. It does not stop analysis of later commands or other working directories. Audit details show the missing target, working directory, and applicable `cd` outcome. The analyzer retains both outcomes of an unguarded `cd`.

The model assesses effects that the parser cannot resolve. Incomplete parsing alone does not require user approval. The model must identify any effect or authority that remains unclear. Unreadable helpers, explicit restrictions, and unauthorized actions still require escalation.

The optional [Python analyzer](python-parser.md) resolves bounded functions, loops, branches, file effects, and process calls. Imports have separate grants. Unknown Python effects go to the model with bounded source context.

Repository, secret, policy, Beads, and test operations remain distinct. Reading `AGENTS.md` is allowed by default. A symlink to secret material still requires a secret read grant.

This system does not enforce permissions at the operating-system level. Files or environment state can change between review and actual execution.

## Control flow and filename lists

The gate can approve a union of possible effects. It does not need to predict which branch succeeds when every possible effect has permission.

Working directories, path values, calls, and condition effects remain part of analysis. Unknown values only prevent approval when they can hide an effect.

The shell adapter supports builtin `exit` with a literal status. It preserves termination within that shell and keeps pipeline termination separate. Fallible exit redirections remain incomplete.

A `while read -r name` loop can use a bounded, newline-terminated filename list. The host records the content hash of an existing manifest. It does not execute the producer command.

Generated manifests can use literal `printf`, shallow `find`, a supported prefix-removal `sed`, and C-locale `sort`. Their values and directory evidence remain in the audit.

Unknown producers, changed manifests, and oversized lists require model review when loop effects depend on the list. Input-independent loop bodies can combine their fixed effects without resolving the input values.

These rules check permission coverage. They do not prove that the command succeeds or terminates.

## Storage migration

Version 3 stores no legacy command-specific approvals or observations. The first read backs up each version 2 store before migration. Backups remain beside the store with a `.backup` suffix and owner-only permissions.

Bounded file, Beads, and test rules keep their scope and provenance. Verified worktree observations merge by repository and relative target. Native interpreter wildcards create no imported grant. Without complete static analysis, those requests remain subject to model review.

Legacy command-specific Always ask rules cannot safely become atomic rules automatically. Such a restriction retains an escalation guard (`legacyShellAsk` or `legacyNativeAsk`) until an administrator replaces it with explicit atomic restrictions. Remove that guard only after restoring the intended restrictions. Normal allow and Dynamic migrations need no manual step.

The model receives the current request, authority context, relevant atomic permissions, and candidate scopes. Unrelated grant history and repeated native permission records remain outside its prompt. Detailed analysis remains available in the private audit.

The prompt identifies the pending grant IDs and any unknown effects. Already allowed effects appear in groups by operation, target type, and repository scope. Groups retain every exact target. They do not grant access to adjacent paths or other worktrees. Repeated rule records stay in the audit.

Repeated parser diagnostics share one entry with their source locations and occurrence counts. Different working directories, branch outcomes, targets, and source files remain distinct. The full command, available helper sources, user messages, and delegation text remain in the request. Current user restrictions still apply to already allowed effects.

This presentation does not change rule matching, candidate IDs, or checks for changed evidence. The audit records the original analysis, prompt size, pending IDs, and counts before and after grouping. This step adds no total prompt limit.

## Grant audit details

The audit stores a compact grant snapshot before large command and helper evidence. It records parse coverage, unresolved commands, atomic grants, and the rules that matched at decision time.

After a successful model rule save, the audit records the previous and new exact rules. It also resolves affected grants before and after that transaction. A proposed rule does not count as saved. Audit enrichment cannot block the store transaction.

Audit storage has no daily quota, per-record size cap, capture truncation, or automatic expiry. It retains complete captured evidence after secret redaction. Files remain private and readers verify their hashes. Terminal views still use pagination and bounded log-tail reads. These do not remove stored evidence. Older records can still report missing or truncated details from earlier versions.

`oc-approvals --details` displays these snapshots as readable text. `--json` includes the full stored payload. Missing, truncated, or unavailable evidence remains explicit. For older save events, the pretty viewer can recover earlier analysis from the same request within its bounded log scan.

## Audit maintenance

Audit writes schedule a metadata scan in the background. Scans run at most once every five minutes per process. They count daily summaries, detail files, and warning markers. They do not inspect unrelated files or follow links.

A `maintenance` record reports storage above 1 GiB or a UTC day older than 14 days. The CLI and TUI display it as a warning. It has no permission outcome and cannot trigger an approval notification. Private marker files suppress repeat warnings for the same UTC day and threshold set across processes. Maintenance errors do not change permission decisions.

`oc-approvals vacuum` removes whole UTC days older than `--keep-days`, which defaults to 14. `--max-size` can select additional prior days, oldest first. The current UTC day stays on disk. Use `--dry-run` to report candidate files and bytes without changing the audit directory. Use `--json` to return the plan as structured data.

Vacuum reads retained summaries and preserves any older detail files that they reference. Thus, cleanup can leave storage above the requested size. The result reports this condition.

Vacuum checks file ownership, permissions, types, and metadata before deletion. It stops if data changes or retained JSON is invalid. Run vacuum while OpenCode is idle. Unrelated files and directories stay unchanged.
