# Tests

## Local checks

```sh
npm ci
npm run build:parser
npm run check
npm test
npm run test:install
npm run test:native
npm run test:tui
```

The Node tests exercise rule precedence, scope migration, parser boundaries, audit handling, transport validation, and asynchronous races.

Native tests start OpenCode 2.0.2 from the pinned development dependency. They create isolated profiles, repositories, credentials, and loopback services. The tests do not open your sessions or invoke a real model.

The grant tree test uses a pseudoterminal. It verifies tree rendering and saved rule changes. Notification tests verify delivery decisions with a stub. They do not send operating-system notifications.

Native tests require Git, Bash, Python, and SQLite on `PATH`. The static fixtures also use `/usr/bin/git` and `/usr/bin/python3`. Each temporary fixture path appears in its result for local diagnosis.

## Model contract tests

Set these environment variables through your normal secret manager:

| Variable                   | Meaning                                                 |
| -------------------------- | ------------------------------------------------------- |
| `APPROVAL_MODEL_BASE_URL`  | HTTPS Chat Completions base URL, ending in `/v1`        |
| `APPROVAL_MODEL_API_KEY`   | Credential for a dedicated test identity                |
| `APPROVAL_MODEL_ID`        | Provider model identifier                               |
| `APPROVAL_MODEL_REASONING` | Reasoning effort, default `medium`                      |
| `APPROVAL_MODEL_REPORT`    | Optional output path, default `test-results/model.json` |

```sh
npm run test:model
```

The model test uses ten synthetic requests. These cover repeated reads, test execution, explicit deployment authority, one-time limits, unavailable helpers, and prompt injection. Proposed commands are data only. The evaluator does not execute them.

A malformed response or unexpected decision fails the test. The suite reports each decision and its latency. It does not retry until a test passes.

These fixtures are regression checks, not proof that a model will classify all real requests correctly.

## GitHub Actions

The workflow runs on the dedicated `opencode-auto-approve` infrastructure runner label. Tests run on ARM64 Linux. macOS support also has local test coverage.

The runner image contains Python, SQLite, and system shell tools. Pinned setup actions install Node and Go. `npm ci` installs dependencies from the lockfile.

Repository variables provide the endpoint, model identifier, and reasoning effort. The API key is a repository Actions secret. Only the model test step receives it.

The workflow accepts trusted pushes to `main` and manual runs of `main`. It has no pull request trigger. Review contributor changes before admitting them to that branch. Do not modify the workflow to execute untrusted code inside the home infrastructure.

CI uploads only the synthetic model report. It does not upload raw audit files, temporary profiles, or service credentials.

Runner manifests and the image definition live in the separate infrastructure repository. The pool uses ephemeral pods, an unprivileged user, restricted network access, and no Docker daemon.
