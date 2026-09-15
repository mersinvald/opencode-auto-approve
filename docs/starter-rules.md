# Starter rules

The plugin includes a starter policy. The normal installer enables it without a separate rule import.

These defaults come from the original working setup. Targets follow the current session, its scratch directory, and your configured skill roots. They contain no personal paths or model credentials.

The [global rule generator](../grant-gate.mjs) is the source of truth. The [model instructions](../grant-decision.mjs) also ship with the plugin.

## What can pass immediately

| Scope                                      | Default permissions                                                            |
| ------------------------------------------ | ------------------------------------------------------------------------------ |
| An ordinary `AGENTS.md` file, anywhere     | Read instructions through `instructions.read`.                                 |
| Executable names on `PATH`                 | Locate names with `shell.lookup`. This does not permit program execution.      |
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

`which pytest` requests `shell.lookup` for the name `pytest`. The parser supports command names, multiple names, `-a`, and the `--` separator. It does not run the lookup or the named program during approval. A missing program is also a lookup. Output redirects and later commands require their own grants.

The parser verifies the external lookup executable or the Zsh builtin. Custom wrappers, path operands, and other flags require model review.

A path rule does not cover a similarly named sibling directory. A grant for `/work/app` does not cover `/work/app-backup`.

## Temporary test output

Call `approval_scratch` from each worker session. Use its returned directory for pytest `--basetemp`, caches, and disposable test output.

Pytest can delete an existing basetemp directory. That operation needs `files.delete` as well as the test execution permission.

The worker scratch already has this permission. Ancestor scratch directories have automatic read access only. Reusing its path can require another model decision for each new test directory.

Keep shared deliverables at their assigned paths. Other sessions can read these artifacts without sharing its cleanup permission.

## Sed reads and edits

The shell parser converts supported `sed` commands into the same file grants used by native reads and edits. It does not create a separate permission for each expression.

| Command                                     | Requested grants                              |
| ------------------------------------------- | --------------------------------------------- |
| `sed -n '1,20p' file`                       | Read `file`.                                  |
| `sed -E -e 's/old/new/g' -e '/skip/d' file` | Read `file`; output goes to the shell stream. |
| `sed -i '' 's/old/new/' file` on macOS      | Read and write `file`.                        |
| `sed -i 's/old/new/' file` with GNU sed     | Read and write `file`.                        |
| `sed -i.bak 's/old/new/' file`              | Read and write `file`, plus write `file.bak`. |
| `sed 'r extra' file`                        | Read `file` and `extra`.                      |
| `sed 's/old/new/w output' file`             | Read `file` and write `output`.               |

Existing rules decide the result: all requested grants must allow the action for it to pass immediately. An Always ask rule goes to the user. An ungranted effect goes to the model. Backup destinations, secrets, protected files, and read-only roles retain their permission boundaries.

Supported expressions include addresses and ranges, print and delete commands, substitutions with common delimiters, multiple `-e` expressions, command blocks, and literal `r`/`w` targets. The parser unions the file effects across branches without running sed. It recognizes the different macOS and GNU `-i` argument conventions.

External script files (`-f`), text insertion commands (`a`, `i`, `c`), execution (`e` or `s///e`), ambiguous filenames, and syntax the parser cannot fully account for go to model review. In-place edits through a final symlink, backup path templates, and commands that mutate their own glob or executable inputs also require review.

See the [GNU sed reference](https://www.gnu.org/software/sed/manual/sed.html) and [BSD sed reference](https://man.freebsd.org/cgi/man.cgi?query=sed&sektion=1) for command syntax.

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
