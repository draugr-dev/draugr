# Changelog

All notable, user-facing changes to Draugr. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

Each release's notes are written for **users first** (what you can do, what changed for
you), with technical detail linked from the commit history. Keep an `Unreleased` section
and move it under a version on release.

## [Unreleased]

_Nothing yet._

## [0.6.0] - 2026-07-13

### Added

- **`draugr classify`** — a guided wizard that asks a few questions about each component and
  writes its `exposure` and `criticality` back into the Saga (comments and formatting
  preserved). The easy way to set up prioritization without hand-editing the descriptor.

### Changed

- **Breaking:** component risk classification now uses readable labels instead of codes —
  `exposure: public | authenticated | internal | restricted` and
  `criticality: critical | important | supporting` (was `re1`–`re4` / `bc1`–`bc3`). They're
  self-documenting in the descriptor and reports. Pre-1.0 change — update any descriptors
  that used the old codes.

## [0.5.0] - 2026-07-13

### Added

- **Finding prioritization** — declare a component's `exposure` and `criticality` and Draugr
  ranks every finding into a priority band (P1–P4) by combining its severity with how exposed
  and how business-critical its component is. The report includes `priorities` counts, and
  `draugr scan --min-priority P2` lists just the findings worth acting on now. Unclassified
  components are treated as high-risk so nothing slips.
- **Priority gating** — `draugr scan --fail-on-priority P1` fails the gate on any finding at
  or above a priority band. Because priority already folds in a component's exposure and
  criticality, this gates per component without per-component config; it composes with
  `--fail-on` (the run fails if either trips).

### Changed

- Merged SARIF output now preserves each finding's numeric **`security-severity`** score
  (read from the scanner and re-emitted), so GitHub / GitLab / Azure DevOps rank Draugr's
  findings by their real CVSS-style severity instead of a coarse pass/fail level.

## [0.4.0] - 2026-07-12

### Added

- **IaC scanning** (`iac` control, via [Trivy](https://trivy.dev) config mode): scans a
  component's repositories for insecure Infrastructure as Code — Terraform, Kubernetes
  manifests, Dockerfiles, Helm, and more. Requires `trivy` on your `PATH`.

### Fixed

- In-source scanner suppressions are now honored: results a scanner marks as suppressed
  (e.g. Semgrep `// nosem` comments) are dropped instead of counted, so intentional,
  justified exceptions no longer fail the gate.

## [0.3.0] - 2026-07-11

### Added

- **Static analysis** (`sast` control, via [Semgrep](https://semgrep.dev)): scans a
  component's repositories for security bugs in your own source code (injection, unsafe APIs,
  and more). Requires `semgrep` on your `PATH`.

### Fixed

- SARIF results that omit a severity level now inherit it from the rule definition (per the
  SARIF spec), so Semgrep's error-level findings are correctly reported as errors and fail
  the gate — instead of all being downgraded to warnings.

## [0.2.0] - 2026-07-11

### Added

- **Secret detection** (`secrets` control, via [Gitleaks](https://github.com/gitleaks/gitleaks)):
  scans a component's repositories for leaked credentials — API keys, tokens, private keys.
  Any detected secret **fails the gate** regardless of how the scanner rated it. Requires
  `gitleaks` on your `PATH`.

### Changed

- The **self-scan** CI now dogfoods the **latest** Draugr release automatically (no pinned
  version), so new controls take effect as soon as they ship.

## [0.1.0] - 2026-07-11

First public preview of Draugr.

### Highlights

- **Describe your app, scan it, get a verdict.** Write a `draugr.saga.yaml`, run
  `draugr scan`, and get pass/fail evidence as JSON + SARIF.
- **Container image scanning** (`images`, via Trivy) and **dependency scanning / SCA**
  (`sca`, via Trivy) work out of the box.
- **Discovery — "the Ravens":** `draugr survey` writes the descriptor for you from a
  Kubernetes cluster or a GitHub organization.
- **Cheap at scale:** content-hash caching means unchanged components are never re-scanned.
- **CI-ready:** exits non-zero on a failing verdict, and results are SARIF, so they flow
  straight into GitHub / GitLab / Azure DevOps security dashboards.

### Added

- Commands: `draugr scan`, `draugr survey`, `draugr version`.
- Controls: `images`, `sca`. Scanners: `trivy`, `trivy-fs`. Surveyors: `k8s-images`,
  `github-org-repos`.
- Policy gate with `--fail-on`; JSON + merged SARIF reports (`--output`).
- Content-hash caching (`--cache-dir`); structured logs and opt-in OpenTelemetry.

### Notes

- **Early preview** — the CLI and the Saga schema may change before 1.0.
- Requires **Trivy** on your `PATH` (and `git` for repository scans).

[Unreleased]: https://github.com/draugr-dev/draugr/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.6.0
[0.5.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.5.0
[0.4.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.4.0
[0.3.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.3.0
[0.2.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.2.0
[0.1.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.1.0
