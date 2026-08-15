---
title: Integrations catalog
description: Every controller, scanner, surveyor, reporter, and publisher Draugr ships or plans.
section: Reference
order: 30
---

# Integrations catalog

The single place to navigate every [**controller**](../concepts/controls-and-scanners.md#controllers),
[**scanner**](../concepts/controls-and-scanners.md#scanners), and [**surveyor**](../concepts/surveyors.md)
Draugr ships or plans (new to these terms? see [concepts](../concepts/saga.md)). Each component has a
**markdown doc kept next to its implementation** — what it is, which control it relates to,
links, and license/terms.

> **Convention:** every new scanner/controller/surveyor ships a colocated `.md` (e.g.
> `internal/scanners/<name>.md`) covering: what it does · control · tool + links ·
> **license & terms of use** · integration notes. Add a row here too.

See also: [control taxonomy](../contributing/naming.md#security-controls-taxonomy) ·
[glossary](glossary.md).

**Who publishes what.** `draugr controls` ends with a roster grouping every scanner by the project
that publishes its tool — `aquasecurity` for the Trivy family and kube-bench, `projectdiscovery`
for Nuclei, and `draugr` for the ones whose detection logic is our own and which need no external
tool at all. Reading the control table those look alike, and one of them is somebody else's binary
executing on your machine, which is a question worth being able to answer without reading source.

## Controllers

| Control | Industry term | Scope | Status | Scanner(s) | Doc |
|---------|---------------|-------|:------:|------------|-----|
| `images` | Container image scanning | component | ✅ | `trivy` (default), `grype` (opt-in) | [doc](../../internal/controllers/images.md) |
| `sca` | Software Composition Analysis | component | ✅ | `trivy-fs` (default), `grype-fs` (opt-in), `retirejs` (opt-in), `mend-sca` (opt-in) | [doc](../../internal/controllers/sca.md) |
| `sast` | Static Application Security Testing | component | ✅ | `semgrep` (default), `gosec` (opt-in) | [doc](../../internal/controllers/sast.md) |
| `secrets` | Secret detection | component | ✅ | `gitleaks` | [doc](../../internal/controllers/secrets.md) |
| `iac` | IaC / misconfiguration | component | ✅ | `trivy-config` | [doc](../../internal/controllers/iac.md) |
| `headers` | HTTP security headers | component | ✅ | `draugr-headers` (native) | [doc](../../internal/controllers/headers.md) |
| `dast` | Dynamic Application Security Testing | component | ✅ | `nuclei` | [doc](../../internal/controllers/dast.md) |
| `infrastructure` | CIS benchmarks / posture | component | ✅ | `draugr-k8s-policies` (default), `kube-bench` and `kube-bench-job` (opt-in) | [doc](../../internal/controllers/infrastructure.md) |
| `tls` | TLS/certificate assessment | component | ✅ | `draugr-tls` (native) | [doc](../../internal/controllers/tls.md) |
| `licenses` | Dependency licence compliance | component | ✅ | `trivy-license` (default), `mend-licenses` (opt-in) | [doc](../../internal/controllers/licenses.md) |
| `threats` | Threat intelligence | component | ✅ | `urlhaus` (default), `virustotal` (opt-in) | [doc](../../internal/controllers/threats.md) |

`licenses` is a control rather than part of `sca` because licence risk isn't a vulnerability —
the exposure is legal, the policy is owned by different people, and
[`config.gate`](saga-schema.md#configgate) can then hold it to its own threshold.

**SBOM generation is not in this table on purpose.** Every control above checks something and
returns a verdict that feeds the gate. An SBOM is an inventory — it finds nothing, so it has no
verdict to give, and a row here would always read "pass" without ever having looked. It is
configured separately as `config.sbom` and travels as evidence. See
[the Saga reference](saga-schema.md#sbom-generation).

## Scanners

| Scanner | Control | Tool | License | Status | Doc |
|---------|---------|------|---------|:------:|-----|
| `trivy` | images | Aqua Trivy | Apache-2.0 | ✅ | [doc](../../internal/scanners/trivy.md) |
| `trivy-fs` | sca | Aqua Trivy (fs) | Apache-2.0 | ✅ | [doc](../../internal/scanners/trivy-fs.md) |
| `grype` | images | Anchore Grype | Apache-2.0 | ✅ | [doc](../../internal/scanners/grype.md) |
| `grype-fs` | sca | Anchore Grype (dir) | Apache-2.0 | ✅ | [doc](../../internal/scanners/grype-fs.md) |
| `retirejs` | sca | retire.js (binary: `retire`, from npm) | Apache-2.0 | ✅ | [doc](../../internal/scanners/retirejs.md) |
| `gitleaks` | secrets | Gitleaks | MIT | ✅ | [doc](../../internal/scanners/gitleaks.md) |
| `semgrep` | sast | Semgrep | LGPL-2.1 | ✅ | [doc](../../internal/scanners/semgrep.md) |
| `gosec` | sast | gosec (Go) | Apache-2.0 | ✅ | [doc](../../internal/scanners/gosec.md) |
| `mend-sca` | sca | Mend CLI (Unified Agent) | proprietary | ✅ | [doc](../../internal/scanners/mend-sca.md) |
| `mend-licenses` | licenses | Mend CLI (Unified Agent) | proprietary | ✅ | [doc](../../internal/scanners/mend-licenses.md) |
| `trivy-config` | iac | Aqua Trivy (config) | Apache-2.0 | ✅ | [doc](../../internal/scanners/trivy-config.md) |
| `trivy-license` | licenses | Aqua Trivy (licence) | Apache-2.0 | ✅ | [doc](../../internal/scanners/trivy-license.md) |
| `kube-bench` | infrastructure | Aqua kube-bench | Apache-2.0 | ✅ | [doc](../../internal/scanners/kube-bench.md) |
| `kube-bench-job` | infrastructure | Aqua kube-bench (in-cluster Job) | Apache-2.0 | ✅ | [doc](../../internal/scanners/kube-bench-job.md) |
| `draugr-k8s-policies` | infrastructure | native (no tool) | Apache-2.0 | ✅ | [doc](../../internal/scanners/draugr-k8s-policies.md) |
| `draugr-headers` | headers | native (no tool) | Apache-2.0 | ✅ | [doc](../../internal/scanners/draugr-headers.md) |
| `nuclei` | dast | ProjectDiscovery Nuclei | MIT | ✅ | [doc](../../internal/scanners/nuclei.md) |
| `draugr-tls` | tls | native (no tool) | Apache-2.0 | ✅ | [doc](../../internal/scanners/draugr-tls.md) |
| `urlhaus` | threats | abuse.ch URLhaus (hosted API, free key) | data: abuse.ch terms | ✅ | [doc](../../internal/scanners/urlhaus.md) |
| `virustotal` | threats | VirusTotal (hosted API, free key) | data: VirusTotal/Google terms | ✅ | [doc](../../internal/scanners/virustotal.md) |

## Surveyors

| Surveyor | Discovers | Auth | Status | Doc |
|----------|-----------|------|:------:|-----|
| `k8s-images` | container images (with running digests) in a k8s cluster | kubeconfig | ✅ | [doc](../../internal/surveyors/k8s-images.md) |
| `k8s-cluster` | the cluster itself, as an `infrastructure` component | kubeconfig | ✅ | [doc](../../internal/surveyors/k8s-cluster.md) |
| `github-org-repos` | repositories in a GitHub org | `GITHUB_TOKEN` | ✅ | [doc](../../internal/surveyors/github-org-repos.md) |
| `gitlab-group-projects` | projects in a GitLab group, subgroups included | `GITLAB_TOKEN` | ✅ | [doc](../../internal/surveyors/gitlab-group-projects.md) |
| `azure-devops-repos` | Git repositories in an Azure DevOps organization or project | `AZURE_DEVOPS_EXT_PAT` | ✅ | [doc](../../internal/surveyors/azure-devops-repos.md) |

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
| `gitlab-sast` | GitLab's own security schema, for its Vulnerability Report (a build artifact, not an upload) |
| `gitlab-dependency-scanning` | the same, for vulnerable dependencies |
| `gitlab-secret-detection` | the same, for leaked credentials |
| `gitlab-container-scanning` | the same, for vulnerable packages in a container image |
| `gitlab-codequality` | GitLab Code Quality — every finding, in the merge request, on any tier |
| `template` | custom payload from a Go `text/template` (inline or file) — no code needed |

`-o/--output <dir>` also writes `report.json` + `results.sarif`.

## Publishers

A **Publisher** delivers rendered reports to a destination — the "where" of reporting, separate
from the Reporter (the "what"). Configure them in the Saga's
[`config.reports` / `config.publishers`](saga-schema.md#configreports-and-configpublishers);
every rendered report is delivered to every publisher.

| Kind | Delivers to | Config |
|------|-------------|--------|
| `file` | a local directory (one file per report format) | `dir` |
| `github` | GitHub code scanning (uploads the `sarif` report to the Security tab) | `repo`, `commit`, `ref` (default from the GitHub Actions env); token from `$GITHUB_TOKEN` (or `tokenEnv`) |
| `github-pr-comment` | a sticky pull-request comment (posts the `markdown` report) | `repo`, `pr` (default from the env); token from `$GITHUB_TOKEN` (or `tokenEnv`) |
| `azure-pr-comment` | a sticky Azure DevOps pull-request comment (posts the `markdown` report) | `org`, `project`, `repo`, `pr` (default from the Azure Pipelines env); token from `$SYSTEM_ACCESSTOKEN` (or `tokenEnv`) |
| `gitlab-mr-comment` | a sticky GitLab merge-request comment (posts the `markdown` report) | `repo`, `pr` (default from the GitLab CI env); token from `$GITLAB_TOKEN` (or `tokenEnv`) |

No publisher stores a secret in the Saga — every token comes from an environment variable, and
each no-ops outside its own context (not in CI, or no PR) so the same Saga still runs locally.
Every comment publisher upserts one **sticky** comment (updated in place on each push rather
than posting a new one) and pairs with
[`draugr diff --publish`](cli.md#draugr-diff-basesarif-headsarif) for a PR security delta. Code
scanning is free for public repos; private repos need GitHub Advanced Security.

See [`examples/reporting.saga.yaml`](../../examples/reporting.saga.yaml) for a multi-format,
multi-publisher Saga, [`examples/github-actions-code-scanning.yml`](../../examples/github-actions-code-scanning.yml)
and [`examples/gitlab-ci.yml`](../../examples/gitlab-ci.yml)
for the matching workflow. Draugr dogfoods this itself in
[`.draugr/self.saga.yaml`](../../.draugr/self.saga.yaml) + the self-scan workflow.

Publishers that need managed credentials or an authenticated integration (ServiceNow, Jira,
Splunk, signed webhooks) are out of scope here: each needs secret handling and a service to
hold it, which is not what a CLI that runs in your pipeline should be doing.

## Utilities

Not scanners, but tools Draugr provisions/uses:

| Tool | Purpose | Install |
|------|---------|:------:|
| `cosign` | verify release/tool signatures (Sigstore) | `draugr tools install cosign` |
| `git` | check out repositories for repo-scanning controls | system |
| `kubectl` | required by the `kube-bench` scanner, whose `policies` checks shell out to it | system |
| `syft` | generate SBOMs when a Saga sets `config.sbom` | `draugr tools install syft` |

---

**New to a category?** [Learn](/learn/) explains what each control is for and when it matters,
independent of Draugr's implementation of it.
