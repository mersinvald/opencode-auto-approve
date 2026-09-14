# Security

This plugin assists permission decisions. It is not an operating-system sandbox or a substitute for human judgment.

## Trust boundaries

- A review model can misread instructions or accept misleading content.
- Candidate and response validation restrict output shape and scope. They do not prove intent or command safety.
- Static analysis covers a bounded grammar. Unknown effects fall back to model review.
- The command executes later in the normal OpenCode environment. State can change after review.
- Native denies and explicit Always ask rules remain user boundaries.
- A native allow or a tool without permission checks can bypass this plugin.

Start with shadow mode. Inspect decisions before you enable automatic approval. Review remembered grants after task or repository changes.

## Data sent to the model

Review context can include commands, paths, user instructions, delegated requirements, helper source, and prior permission rules. Use an endpoint that you trust with this data.

The plugin excludes model hidden reasoning from its audit records. It redacts common credentials, but pattern-based redaction cannot identify every secret.

Audit files and installer backups are private operational data. Do not attach raw audit directories to public issues. Replace identifiers and file contents with synthetic fixtures first.

## CI boundary

The public workflow runs on trusted pushes to `main` and manual runs of `main`. It does not subscribe to pull request events. Model credentials belong in Actions secrets, never source files.

The dedicated infrastructure runner is ephemeral and unprivileged. It has no Docker socket, host filesystem mounts, or Kubernetes service account token. Its network policy limits internal access to the model ingress.

Do not add a pull request trigger that executes untrusted code on this pool. Do not use `pull_request_target` to check out a contributor branch. Test a reviewed change only after a maintainer admits it to a trusted branch.

See the GitHub [self-hosted runner security guidance](https://docs.github.com/en/actions/reference/security/secure-use).

## Report a vulnerability

Use the private vulnerability reporting feature of this repository. Do not put credentials or an exploit against a live endpoint in a public issue.
