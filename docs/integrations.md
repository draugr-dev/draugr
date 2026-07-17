# Integrations catalog

The single place to navigate every [**controller**](concepts.md#controllers),
[**scanner**](concepts.md#scanners), and [**surveyor**](concepts.md#surveyors--the-ravens)
Draugr ships or plans (new to these terms? see [concepts](concepts.md)). Each component has a
**markdown doc kept next to its implementation** — what it is, which control it relates to,
links, and license/terms.

> **Convention:** every new scanner/controller/surveyor ships a colocated `.md` (e.g.
> `internal/scanners/<name>.md`) covering: what it does · control · tool + links ·
> **license & terms of use** · integration notes. Add a row here too.

See also: [control taxonomy](naming.md#security-controls-taxonomy) ·
[glossary](glossary.md).

## Controllers

| Control | Industry term | Scope | Status | Scanner(s) | Doc |
|---------|---------------|-------|:------:|------------|-----|
| `images` | Container image scanning | component | ✅ | `trivy` | [doc](../internal/controllers/images.md) |
| `sca` | Software Composition Analysis | component | ✅ | `trivy-fs` | [doc](../internal/controllers/sca.md) |
| `sast` | Static Application Security Testing | component | ✅ | `semgrep` (default), `gosec` (opt-in) | [doc](../internal/controllers/sast.md) |
| `secrets` | Secret detection | component | ✅ | `gitleaks` | [doc](../internal/controllers/secrets.md) |
| `iac` | IaC / misconfiguration | component | ✅ | `trivy-config` | [doc](../internal/controllers/iac.md) |
| `headers` | HTTP security headers | component | ✅ | `http-headers` (native) | [doc](../internal/controllers/headers.md) |
| `dast` | Dynamic Application Security Testing | component | 🗺️ [#54](https://github.com/draugr-dev/draugr/issues/54) | OWASP ZAP | — |
| `infrastructure` | CIS benchmarks / posture | project | 🗺️ [#55](https://github.com/draugr-dev/draugr/issues/55) | kube-bench | — |
| `tls` | TLS/certificate assessment | component | 🗺️ [#56](https://github.com/draugr-dev/draugr/issues/56) | testssl.sh | — |
| `sbom` | Software Bill of Materials | component | 🗺️ [#57](https://github.com/draugr-dev/draugr/issues/57) | Syft | — |
| `threats` | Threat intelligence | component | 🗺️ [#59](https://github.com/draugr-dev/draugr/issues/59) | URLhaus, VirusTotal | — |

## Scanners

| Scanner | Control | Tool | License | Status | Doc |
|---------|---------|------|---------|:------:|-----|
| `trivy` | images | Aqua Trivy | Apache-2.0 | ✅ | [doc](../internal/scanners/trivy.md) |
| `trivy-fs` | sca | Aqua Trivy (fs) | Apache-2.0 | ✅ | [doc](../internal/scanners/trivy-fs.md) |
| `gitleaks` | secrets | Gitleaks | MIT | ✅ | [doc](../internal/scanners/gitleaks.md) |
| `semgrep` | sast | Semgrep | LGPL-2.1 | ✅ | [doc](../internal/scanners/semgrep.md) |
| `gosec` | sast | gosec (Go) | Apache-2.0 | ✅ | [doc](../internal/scanners/gosec.md) |
| `trivy-config` | iac | Aqua Trivy (config) | Apache-2.0 | ✅ | [doc](../internal/scanners/trivy-config.md) |
| `http-headers` | headers | native (no tool) | Apache-2.0 | ✅ | [doc](../internal/scanners/http-headers.md) |

## Surveyors (the Ravens)

| Surveyor | Discovers | Auth | Status | Doc |
|----------|-----------|------|:------:|-----|
| `k8s-images` | container images (with running digests) in a k8s cluster | kubeconfig | ✅ | [doc](../internal/surveyors/k8s-images.md) |
| `github-org-repos` | repositories in a GitHub org | `GITHUB_TOKEN` | ✅ | [doc](../internal/surveyors/github-org-repos.md) |

## Reporters

Scan results render through a pluggable **Reporter** interface (`pkg/report`), selected with
`draugr scan --format`:

| Format | Purpose |
|--------|---------|
| `console` | human summary on stdout (default) — verdict, P1–P4 counts, "fix first" |
| `markdown` | portable report for MR comments, wikis, Slack |
| `html` | self-contained HTML report (inline CSS) — a shareable, browser-viewable artifact |
| `junit` | JUnit XML — surfaces findings in CI test panels (GitLab, Jenkins, Azure DevOps…) |
| `json` | machine-readable report |
| `sarif` | SARIF 2.1.0 for code-scanning dashboards |

`-o/--output <dir>` also writes `report.json` + `results.sarif`. Publishers (deliver a report to
a destination) and more formats are tracked in [#58](https://github.com/draugr-dev/draugr/issues/58).

## Utilities

Not scanners, but tools Draugr provisions/uses:

| Tool | Purpose | Install |
|------|---------|:------:|
| `cosign` | verify release/tool signatures (Sigstore) | `draugr tools install cosign` |
| `git` | check out repositories for repo-scanning controls | system |
