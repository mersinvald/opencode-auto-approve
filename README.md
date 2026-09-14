# OpenCode Auto Approve

Scoped permission review for **OpenCode 2.0.2** on macOS and Linux.

The plugin checks each native action against permission rules. A bounded shell parser derives operations and targets without executing the command. A review model handles requests that the rules cannot resolve.

The model can allow once, ask the user, or remember an allowed scope. The native approval dialog stays available during review. Your response takes precedence over a pending model response.

This is an approval assistant, not a command sandbox. Model decisions can be wrong. Read the [security boundaries](SECURITY.md) before you enable automatic approval.

## What it includes

- Rules for files, Git, local Beads operations, tests, shell commands, and unknown native actions.
- A project grant tree with **Always allow**, **Always ask**, and **Dynamic** modes.
- Static shell analysis with executable identity checks, bounded expansion, and conservative fallback.
- Background model review with retries, cancellation, and checks for changed requests or rules.
- An audit panel, a terminal viewer, detailed local records, and macOS approval notifications.
- Synthetic tests for permission races, scope reuse, malformed responses, and model decisions.

Existing bounded permissions retain their scope during import. Broad interpreter permissions become Dynamic rules in the plugin store. See [configuration](docs/configuration.md) for native permissions that bypass this store.

## Install

Requirements: Node.js 22 or later, Python 3.10 or later, Go 1.26 or later, and OpenCode **2.0.2**.

OpenCode 1.x uses a different plugin API. This release does not support it. This release does not support Windows.

1. Clone this repository into a directory that you will keep.

   ```sh
   git clone https://github.com/mersinvald/opencode-auto-approve.git
   cd opencode-auto-approve
   npm ci
   ```

2. Configure an OpenAI-compatible Chat Completions model in your OpenCode profile.

   The route must support tool calls and a named `reasoning_effort` variant.
   See the [provider example](docs/configuration.md#classifier-provider).

3. Install the plugin in shadow mode with your provider, model, and variant identifiers.

   ```sh
   python3 install.py --provider review --model classifier --variant medium --mode shadow
   python3 build_static.py --config-root "$HOME/.config/opencode"
   ```

4. Restart OpenCode and inspect `/approval-audit`.

   Shadow mode records decisions and leaves native approval requests for you.

5. Enable automatic approval when the audit results match your intended policy.

   ```sh
   python3 install.py --mode enforce
   ```

The installer backs up the files it changes. It preserves existing model settings, grants, and plugin entries. It does not edit Slim or agent prompts.

The installed modules link to the dependencies in this checkout. Keep the checkout and its `node_modules` directory available. Repeat `npm ci` after an update.

## Daily use

| Interface                      | Purpose                                      |
| ------------------------------ | -------------------------------------------- |
| `Ctrl+G` or `/approval-grants` | Inspect project grants and change their mode |
| `/approval-audit`              | Inspect recent permission reviews            |
| `oc-approvals --help`          | Show terminal audit viewer options           |
| Native permission dialog       | Answer immediately while the model reviews   |

In the grant tree, use the arrow keys to navigate. Press **A** to allow, **S** to ask, or **D** for model review. Press **/** to filter.

An Always ask rule goes directly to you. Dynamic permits model review. A remembered rule applies only within the current OpenCode project.

## Documentation

- [Configuration, upgrades, and removal](docs/configuration.md)
- [Decision flow and module map](docs/architecture.md)
- [Tests and infrastructure runners](docs/testing.md)
- [Security and private audit data](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## License

MIT. The shell parser uses `mvdan.cc/sh/v3` under its separate BSD 3-Clause license.
