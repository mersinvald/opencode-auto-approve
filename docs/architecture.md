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

The model selects `allow_once`, `escalate_once`, or `allow_always`. Remembered targets must come from the supplied candidate list. Opaque commands retain their exact input identity.

Repeated consequential operations require explicit user instructions. Routine local scopes can derive from the current task. The model interprets this authorization boundary. Schema validation alone cannot prove that its interpretation is correct.

The background queue retries transient failures with bounded attempts and backoff. Malformed responses receive schema feedback. Exhausted failures leave the native approval request for the user.

The audit viewer checks pending permissions before it sends a notification. It notifies after escalation, terminal review failure, or five minutes without a decision. Native operating-system notifications currently target macOS.

## Module map

| Modules                                           | Responsibility                                              |
| ------------------------------------------------- | ----------------------------------------------------------- |
| `index.mjs`, `review-context.mjs`                 | OpenCode hooks, context, lifecycle, and race checks         |
| `action-grants.mjs`, `shell-*`, `sqlite-read.mjs` | Static action and shell analysis                            |
| `shell-parser/`                                   | Syntax-only Go adapter for mvdan/sh                         |
| `grant-gate.mjs`, `grant-rules.mjs`               | Operation rules, scope precedence, and native restrictions  |
| `grant-store.mjs`, `native-permissions.mjs`       | Private project storage and permission migration            |
| `grant-decision.mjs`, `grant-review.mjs`          | Model contract and reviewed decision validation             |
| `structured-classifier.mjs`                       | Bounded Chat Completions transport and response decoding    |
| `async-review.mjs`, `native-transport.mjs`        | Background review and native pending-request recovery       |
| `audit*.mjs`, `grant-tree-tui.mjs`                | Detailed records, terminal output, and project grant editor |
| `approval-notifications.mjs`                      | Notification decisions and macOS delivery                   |

## Static analysis limits

Known native reads and edits map directly to grants. Unknown native actions produce opaque grants. Unsupported shell syntax also adds an opaque grant instead of assuming safety.

The parser can normalize literal variables, bounded arrays, paths, filters, and limited metadata substitutions. It does not execute the proposed command. Python helpers go to the model as bounded source context. General Python static analysis is not implemented.

Repository, secret, policy, Beads, and test operations remain distinct. Reading `AGENTS.md` is allowed by default. A symlink to secret material still requires a secret read grant.

This system does not enforce permissions at the operating-system level. Files or environment state can change between review and actual execution.
