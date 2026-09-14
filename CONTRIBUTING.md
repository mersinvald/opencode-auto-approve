# Contributing

Keep changes focused on permission behavior, usability, or compatibility. Add a regression fixture for a new command rule or approval failure.

Run the deterministic and native tests before you propose a change. See [testing](docs/testing.md) for commands and model tests.

Use synthetic paths, instructions, and helper programs. Never copy raw session messages or audit records into a fixture. Do not commit endpoint credentials or personal configuration.

A static rule must account for flags, redirections, substitutions, paths, and relevant execution context. Unsupported effects must remain Dynamic. Include rejection tests beside each new allowed form.

Do not weaken a failing assertion to match a model response. Check whether the prompt, contract, transport, or fixture is wrong.

Keep documentation direct. State the action, its scope, and its limit. Use short sentences and one instruction per step.

The maintainers run reviewed changes on trusted infrastructure. Fork pull requests do not receive access to that runner pool or the model secret.
