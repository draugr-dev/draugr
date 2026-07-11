# Changelog

All notable, user-facing changes to Draugr. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

Each release's notes are written for **users first** (what you can do, what changed for
you), with technical detail linked from the commit history. Keep an `Unreleased` section
and move it under a version on release.

## [Unreleased]

_Nothing yet._

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

[Unreleased]: https://github.com/draugr-dev/draugr/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.2.0
[0.1.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.1.0
