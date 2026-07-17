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

- **Draugr scans itself.** On every change, CI runs the latest released Draugr against this
  repository (see [`.draugr/self.saga.yaml`](.draugr/self.saga.yaml)) for dependency
  vulnerabilities (`sca`), leaked secrets (`secrets`), static-analysis bugs (`sast`), and IaC
  misconfigurations (`iac`) — so the tool is held to the standard it enforces for everyone
  else. The results are published to this repo's **code scanning** (Security tab).
- We track our supply-chain posture with the **OpenSSF Scorecard** (a weekly workflow that also
  publishes to code scanning) and hold an **OpenSSF Best Practices** badge.
- Dependencies are scanned for known vulnerabilities (`govulncheck`) and kept current
  (Dependabot).
- Code is statically analyzed for security issues (`gosec` via `golangci-lint`) on every
  change.
- Releases are cosign-signed (Sigstore bundle) with SBOMs and SLSA build provenance.
- Logs and telemetry never carry secrets.

> Maintainers: the Scorecard Branch-Protection check reads settings via an optional
> `SCORECARD_TOKEN` repository secret (a fine-grained PAT with *Administration: read*); without
> it the check is skipped, not failed.

Thank you for helping keep Draugr and its users safe.
