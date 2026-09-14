# Configuration

The [starter rule catalog](starter-rules.md) lists the built-in defaults and optional policy examples. A normal installation includes these defaults automatically.

## Classifier provider

The plugin reads `opencode.json` beside its policy file. The file must belong to the current user and have mode `0600`.

This example shows the required structure. Replace the URL and model identifier with your provider values.

```json
{
  "providers": {
    "review": {
      "npm": "@opencode/ai/providers/openai-compatible.js",
      "settings": {
        "baseURL": "https://model.example.com/v1",
        "apiKey": "{env:REVIEW_API_KEY}"
      },
      "models": {
        "classifier": {
          "modelID": "your-model-id",
          "variants": [{ "id": "medium", "body": { "reasoning_effort": "medium" } }]
        }
      }
    }
  }
}
```

Use the provider module path that OpenCode resolves. Its path must end with `/providers/openai-compatible.js`.

The reviewer calls Chat Completions directly. It requires one `review_permission` tool call with valid JSON arguments. It rejects redirects, oversized responses, ambiguous tool calls, and unsupported reasoning variants. HTTPS is required except for loopback fixtures.

The plugin has no default model or hosted account requirement. Select a capable instruction-following model. A smaller model may reduce decision quality even when it returns valid JSON.

## Installer options

```sh
python3 install.py --help
python3 build_static.py --help
```

| Option                               | Behavior                                                                              |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| `--config-root`                      | Profile directory. Defaults to `$XDG_CONFIG_HOME/opencode` or `~/.config/opencode`    |
| `--provider`, `--model`, `--variant` | Required on first installation. Explicit values update the classifier selection       |
| `--mode shadow`                      | Record suggestions without automatic replies                                          |
| `--mode enforce`                     | Apply allowed decisions and save approved scopes                                      |
| `--mode off`                         | Disable plugin review. Native permission rules remain                                 |
| `--audit-root`                       | Dedicated audit directory. Defaults to `approval-state/audit` in the profile          |
| `--scratch-root`                     | Dedicated task scratch directory. Defaults to `approval-state/scratch` in the profile |
| `--bin-dir`                          | Destination for `oc-approvals`. Defaults to `~/.local/bin`                            |

An upgrade preserves the existing mode unless you specify `--mode`. Existing audit and scratch paths also stay unchanged.

Resolve competing JSONC files and configuration symlinks before installation. The installer does not merge JSONC or follow these symlinks.

## Policy file

The installer writes `approval-policy.json` with private file permissions. You can edit it while OpenCode is stopped.

| Setting               | Meaning                                                            |
| --------------------- | ------------------------------------------------------------------ |
| `version`             | Policy schema version, currently `1`                               |
| `model`               | Explicit `providerID`, `id`, and `variant`                         |
| `timeoutMs`           | Per-attempt model deadline, up to 60,000 milliseconds              |
| `maxRequestChars`     | Bounded review context budget, up to 64,000 characters             |
| `skillRoots`          | Installed skill directories that permit routine reads              |
| `protectedRoots`      | Policy and plugin paths that require separate security grants      |
| `grantRules`          | Global operation and target rules                                  |
| `modelGrants.enabled` | Whether the model may save rules                                   |
| `staticShell`         | Parser identity, inspected executable pins, and Beads writer roles |

Example global rule:

```json
{
  "operation": "files.read",
  "target": "/path/to/shared/docs",
  "targetType": "directory",
  "mode": "allow"
}
```

Operation and target specificity determine precedence. A project rule can override a broader global rule. Explicit user rules take precedence at equal specificity.

The grant store lives in `approval-rules` beside the policy file. Its files contain project identifiers, observed grants, rules, and provenance.

The default Beads writer role is `orchestrator`. Set `staticShell.beadsWriters` to your coordinator roles, such as `["build"]`, if you use other agent names. File write permission does not grant permission to change Beads state.

## Native permission boundaries

The installer adds native ask rules for shell commands, configured MCP servers, and protected configuration edits. Existing permission entries remain present.

The model cannot override a native deny rule. The plugin also checks role restrictions before approval.

An explicit native allow can bypass the approval dialog before the plugin reviews it. Audit your native rules if you previously allowed `python3 *` or other broad interpreter commands. Importing those rules as Dynamic does not remove the original native entries.

Only requests that reach native permission evaluation can enter this gate. Third-party tools that omit permission checks remain outside its coverage.

## Shell parser and executable pins

```sh
python3 build_static.py --config-root "$HOME/.config/opencode"
```

This builds a local parser and records its SHA-256 hash. A missing or changed parser falls back to model review.

The static engine supports a bounded subset of Bash and Zsh syntax. It examines all feasible branches. It does not run commands or substitute command output during analysis.

System binaries must meet ownership, path, file format, and permission checks. Custom executables require inspected paths and hashes in `staticShell.executables`. Zsh startup files require an inspected `staticShell.zshStartup` profile. The installer never trusts arbitrary startup files automatically.

## Upgrade or remove

1. Update the checkout and run `npm ci`.
2. Run `python3 install.py` to update installed modules.
3. Rebuild the parser with `build_static.py --config-root`.
4. Restart OpenCode.

Backups live in the profile's `backups` directory. They can contain credentials from the original configuration. Keep them private.

To remove the plugin, remove its entries from `opencode.json` and `cli.json`. Remove `oc-approvals` if you no longer need it. Keep native ask rules unless you intend to change those permissions.

Do not restore an entire old configuration over newer unrelated changes. Compare the backup and current files first.
