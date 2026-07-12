# Scanner: `trivy-config` (IaC misconfiguration)

- **Control:** [`iac`](../controllers/iac.md)
- **Tool:** Aqua **Trivy** (config/misconfiguration mode) — https://trivy.dev
- **Status:** ✅ implemented
- **Target:** source repository (`RepositoryTarget`) — checked out via `internal/git`
- **License / terms:** **Apache-2.0** (permissive). Run via **exec**. The bundled misconfig
  policies have their own terms; see `planning/third-party-tool-licensing.md`.

## What it does

Checks out the component's repository, then runs `trivy config --quiet --format sarif <dir>`
to find insecure **Infrastructure as Code** — Terraform, Kubernetes manifests, Dockerfiles,
Helm charts, CloudFormation, and more. See the
[IaC glossary entry](../../docs/glossary.md#iac-scanning--infrastructure-as-code).

## Links

- Trivy misconfiguration scanning: https://trivy.dev/latest/docs/scanner/misconfiguration/

## Notes

- Integration mode: **exec** over a local checkout; Trivy + `git` must be on `PATH`.
- Trivy exits 0 even when misconfigurations are found (no `--exit-code` set), so findings
  come from the SARIF report; the [`iac`](../controllers/iac.md) controller judges severity.
- [Checkov](https://www.checkov.io) is a planned optional second IaC scanner
  ([#52](https://github.com/draugr-dev/draugr/issues/52)).
