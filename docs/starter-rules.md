# Starter rules

The plugin includes a starter policy. The normal installer enables it without a separate rule import.

These defaults come from the original working setup. Targets follow the current session, its scratch directory, and your configured skill roots. They contain no personal paths or model credentials.

The [global rule generator](../grant-gate.mjs) is the source of truth. The [model instructions](../grant-decision.mjs) also ship with the plugin.

## What can pass immediately

| Scope                                      | Default permissions                                                            |
| ------------------------------------------ | ------------------------------------------------------------------------------ |
| An ordinary `AGENTS.md` file, anywhere     | Read instructions through `instructions.read`.                                 |
| Current session directory and its children | Access, read, list, read-only Git inspection, and supported stream operations. |
| Current task scratch directory             | The same reads, plus file writes and deletion.                                 |
| Verified ancestor scratch directories      | Read access for shared task results. No inherited write permission.            |
| Configured skill directories               | Routine reads. Skill changes and script execution have separate permissions.   |
| Inspected lint helpers                     | Run supported lint invocations when the helper path and hash match.            |
| Agent coordination                         | Questions, delegation, steering, waiting, status, and scratch allocation.      |

The directory read grants are `files.access`, `files.read`, `files.list`, `git.read`, and `shell.stream`.

A static approval requires permission for every derived operation and target. A command with an additional unknown effect still needs model review.

Examples within the session directory:

```sh
cat README.md
rg -n 'validate' src
git status --short
git diff --stat
```

Shell examples require the parser and verified executable identities. Unsupported syntax, flags, or runtime settings fall back to model review.

A path rule does not cover a similarly named sibling directory. A grant for `/work/app` does not cover `/work/app-backup`.

## What remains Dynamic

Project edits, test execution, builds, Beads operations, and unfamiliar native actions do not receive blanket approval from the starter policy.

The model uses the task instructions to approve once, escalate, or remember a bounded project scope. It favors reusable permissions for repeated local work that the task authorizes.

Push, deployment, publication, destructive actions, secrets, and security changes need explicit user authorization. The model may remember those operations only when your instructions authorize repeated use.

A secret file has a separate grant even inside a readable directory. Changes to skills, approval configuration, and other protected paths also use separate grants. Native deny rules and role restrictions still apply.

## Extend the starter policy

Use **Ctrl+G** for permissions that should apply only within the current OpenCode project. Rules that the model remembers also stay within that project.

For a shared policy across projects in one profile, use these optional examples:

- [Shared repository reads](../examples/shared-repository.json): directory access, file reads, listings, Git inspection, and stream operations.
- [Component development](../examples/component-development.json): edits to source and tests, test execution, and local Beads work in one repository.

Each example contains fields for `approval-policy.json`. These are optional policy fragments, not complete profiles. The installer does not apply them automatically.

1. Stop OpenCode before editing its policy file.
2. Back up `approval-policy.json`.
3. Replace each `/path/to/...` target with an absolute path you intend to authorize.
4. Merge the selected `grantRules` entries into the existing array.

5. If using Beads, set `staticShell.beadsWriters` to the roles that may change issue state.
6. Set `mode` to `shadow` to inspect proposed decisions first.
7. Restart OpenCode.

Keep existing parser, executable, model, and other policy settings. The [configuration guide](configuration.md) covers policy fields and native permission boundaries.

Global examples apply across projects in that profile. Existing project rules can override them. Existing native allow rules can bypass plugin review, including in shadow mode.

`tests.run` permits test code and its configuration to execute. Tests can have side effects. It does not sandbox those effects.

## Beads has separate permissions

| Grant          | Supported local operations                            |
| -------------- | ----------------------------------------------------- |
| `beads.read`   | Inspect issues and export data.                       |
| `beads.update` | Update issue fields, metadata, and non-closed status. |
| `beads.manage` | Create or close issues and add dependencies.          |

File edit permission does not authorize a Beads database update. The default writer role is `orchestrator`. A Beads grant cannot override the writer-role restriction.

The static adapter supports a verified local embedded-Dolt backend. Reads require `--readonly` and `--sandbox`. Writes require `--sandbox --dolt-auto-commit off`. Other backends or invocations fall back to model review.

Use direct shell calls to `bd` for clearer analysis. Python wrappers need model review with helper source context.

## Machine-specific settings

The starter policy does not copy executable hashes, Nix paths, startup files, or project grants from another machine.

The parser build records its local hash. Custom executables and lint helpers require inspected local paths and hashes. Zsh also requires a separately inspected startup chain, including for Nix-managed Zsh.

Hash collection alone does not establish trust. Inspect the program or startup chain before adding its pins. The [shell setup guide](configuration.md#shell-parser-and-executable-pins) describes these requirements.

A missing or changed pin causes model review. This setup needs no broad `python3 *`, `bash *`, or `zsh *` approval.
