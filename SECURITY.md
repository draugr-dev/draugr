# Security Policy

We take the security of Draugr seriously — it is, after all, a security tool.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report privately via [GitHub Security Advisories](https://github.com/draugr-dev/draugr/security/advisories/new)
or email **security@draugr.dev**.

We aim to acknowledge reports within 3 business days and to provide a remediation
timeline after triage. Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof of concept if possible),
- affected version(s) or commit.

## Our commitments

- **Draugr scans itself.** CI runs a pinned, released Draugr against this repository (see
  [`.draugr/self.saga.yaml`](.draugr/self.saga.yaml)) for dependency vulnerabilities
  (`sca`) today, with leaked-secret detection (`secrets`) enabled and activating as the
  pinned release is updated — so the tool is held to the standard it enforces for everyone
  else.
- Dependencies are scanned for known vulnerabilities (`govulncheck`) and kept current
  (Dependabot).
- Code is statically analyzed for security issues (`gosec` via `golangci-lint`) on every
  change.
- Logs and telemetry never carry secrets.

Thank you for helping keep Draugr and its users safe.
