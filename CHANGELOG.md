# Changelog

All notable, user-facing changes to Draugr. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

Each release's notes are written for **users first** (what you can do, what changed for
you), with technical detail linked from the commit history. Keep an `Unreleased` section
and move it under a version on release.

## [Unreleased]

### Changed

- **The human report now speaks severity bands (critical/high/medium/low), not SARIF levels.**
  The console/markdown/html per-control counts and the "fix first" list show severity — from the
  CVSS score when a scanner provides one, else derived from the finding's level. The gate
  (`--fail-on`) and machine formats (`json`/`sarif`) still use SARIF levels. See
  [Understanding the report](docs/concepts/verdict-and-gating.md#understanding-the-report).
- **Colored console output on a terminal.** The verdict, priorities, and severities are
  color-coded when stdout is a TTY; set `NO_COLOR` to disable. Piped/redirected output stays plain.

## [0.25.0] - 2026-07-17

### Added

- **Zero-config `draugr scan .`** — point `scan` at a directory (or omit the argument for the
  current one) and Draugr scans that repository with `sca`, `secrets`, `sast`, and `iac` — no Saga
  file required. The 60-second path from install to a verdict.
- **`draugr init`** — scaffold a `draugr.saga.yaml` for your project, detecting the stack (Go →
  gosec, a Dockerfile → an images stub, dependency manifests → SCA) so you start from a sensible,
  commented descriptor. `-o -` prints to stdout; `--force` overwrites.

## [0.24.1] - 2026-07-17

### Fixed

- **Finding messages are now repo-relative too**, not just locations. Some scanners (e.g. Gitleaks)
  embed the absolute checkout path in the message (`…detected secret for file /tmp/draugr-repo-…/x`).
  That leaked temp path is now stripped, so messages are clean and — because they no longer vary by
  the (per-scan) temp directory — `draugr diff` no longer reports an unchanged secret finding as
  both new and fixed (#197).

## [0.24.0] - 2026-07-17

### Added

- **The GitHub Action can provision the scanners itself** — set `tools: true` and the action runs
  `draugr tools install` (Trivy, Gitleaks, gosec) plus Semgrep via pipx before scanning, so a
  workflow needs no per-tool setup steps. Default `false` (unchanged for existing users). This
  makes the upcoming code-scanning **starter workflow** a simple checkout → Draugr → upload-sarif.

## [0.23.0] - 2026-07-17

### Added

- **`github-pr-comment` publisher + `draugr diff --publish`.** Post a security report — or a PR's
  **diff** (new / fixed findings) — as a **sticky pull-request comment** that updates in place on
  each push. `draugr diff base.sarif head.sarif --publish` renders the markdown delta and comments
  it on the PR; a Saga can also add `{ kind: github-pr-comment }` to `config.publishers`. Repo/PR
  come from the GitHub Actions environment and the token from `$GITHUB_TOKEN` (never the Saga); it
  no-ops off a pull request.

### Security

- Bumped `golang.org/x/net` (0.55.0 → 0.56.0) and `golang.org/x/text` (0.37.0 → 0.39.0) to clear
  CVE-2026-46600 and CVE-2026-56852 in transitive dependencies.

## [0.22.0] - 2026-07-17

### Added

- **The GitHub Action forwards `GITHUB_TOKEN` to the scan**, so a Saga's `github` publisher can
  upload SARIF to code scanning with no extra step (grant the job `security-events: write`). See
  `examples/github-actions-code-scanning.yml` and `examples/reporting.saga.yaml`.

### Changed

- **Code-scanning alerts now show which scanner found each issue.** Draugr's SARIF tags every
  rule with `scanner:<name>` (e.g. `scanner:semgrep`, `scanner:trivy`), so a GitHub code scanning
  alert surfaces the originating tool in its Tags — Draugr still reports as a single `Draugr` tool.
- **The `github` publisher no-ops outside GitHub Actions** (when no repo/commit/ref/token is
  resolvable) instead of erroring, so a Saga that publishes to code scanning in CI still runs
  cleanly on a developer's machine.

### Fixed

- **Repository-scan findings now use repo-relative paths.** `sast`/`secrets` findings previously
  carried absolute temp-checkout paths (`/tmp/draugr-repo-…/…`), which GitHub code scanning
  couldn't map to files (no PR annotations, unusable Security-tab entries). Paths are now rewritten
  to be repo-relative.

## [0.21.0] - 2026-07-17

### Added

- **`template` report format — custom payloads with no code.** `--format template` (or a
  `config.reports` entry) renders a [Go `text/template`](https://pkg.go.dev/text/template) against
  a stable view of the scan (`.Verdict`, `.Priorities`, `.Controls`, `.Findings`, …) — for a
  bespoke summary line, a Slack payload, or any custom text. Supply it inline (`--template` /
  `template:`) or from a file (`--template-file` / `templateFile:`).
- **Report publishers — declarative, multi-format, multi-destination output.** A Saga can now
  declare `config.reports` (which formats to render) and `config.publishers` (where to deliver
  them); a scan renders each report once and delivers all of them to every publisher. Reports are
  delivered even when the gate fails, so you always get evidence. Built-in publishers:
  - **`file`** — writes each report to a directory.
  - **`github`** — uploads the `sarif` report to GitHub **code scanning** (the Security tab).
    Repo/commit/ref default to the GitHub Actions environment; the token is read from
    `$GITHUB_TOKEN` (or a `tokenEnv` you name) and never stored in the Saga.

  This completes the pluggable reporting model (#58): pick any report formats and deliver them
  anywhere, no code required.

```yaml
config:
  reports:    [ { format: sarif }, { format: markdown }, { format: html } ]
  publishers: [ { kind: file, dir: ./out } ]
```

## [0.20.0] - 2026-07-17

### Added

- **`draugr diff <base.sarif> <head.sarif>`** — compare two scans and classify every finding as
  **new / fixed / unchanged**, with a delta by severity and priority. The headline use case is a
  PR's security impact vs its base branch. Adds a **differential gate** (`--fail-on-new` /
  `--fail-on-new-priority`) that fails a build only for findings the change *introduces*, not the
  pre-existing backlog — so gating stays adoptable. Renders as `console`, `markdown` (a ready-made
  MR comment), or `json`. Findings are matched line-insensitively, so carried-over findings that
  merely moved lines aren't reported as fixed + new.
- **Two more `draugr scan --format` outputs.** `html` renders a self-contained, browser-viewable
  report (inline CSS, no assets) you can publish as a build artifact; `junit` emits JUnit XML so
  CI systems (GitLab, Jenkins, Azure DevOps…) surface findings in their native test-results panel
  — one `<testsuite>` per control, one failing `<testcase>` per finding. Both plug into the same
  Reporter interface as `console`/`markdown`/`json`/`sarif`.

## [0.19.0] - 2026-07-16

### Added

- **Human-readable report formats, independent of GitHub/ADO.** `draugr scan --format` selects
  the stdout format: **`console`** (a grouped summary — verdict, P1–P4 counts, "fix first"),
  **`markdown`** (portable for GitLab/Bitbucket MR comments, wikis, Slack), plus `json` and
  `sarif`. Built on a new pluggable **Reporter** interface (first slice of #58).

### Changed

- **`draugr scan` now prints the console summary by default** instead of raw JSON — the common
  interactive/CI-log case is now readable at a glance. Use `--format json` (or `--output` for
  `report.json` + `results.sarif`) for machine consumption. `--output` is unchanged.

## [0.18.0] - 2026-07-16

### Added

- **`draugr controls`** — list the security controls Draugr can run: what each checks, its
  scope, and which scanner(s) implement it (default, plus opt-in alternatives like gosec marked
  `*`). Makes it easy to see what Draugr covers and how to enable each control.
- **`draugr tools list` now shows a CONTROLS column** — which control(s) each tool backs (e.g.
  `trivy` → `images,sca,iac`), so it's clear why a given scanner matters. `controls` maps
  control → scanners; `tools list` maps tool → controls.

## [0.17.0] - 2026-07-16

### Added

- **`draugr self-update`** — update the running binary in place to the latest release (or a
  pinned `--version`), verified against the release's SHA-256 checksums and, when the `cosign`
  CLI is present, its keyless signature. `--check` reports current vs latest without changing
  anything; `-y` skips the prompt. Because it replaces the binary you're actually running, it
  avoids the stale-copy/PATH confusion of having draugr installed in two places. (CI should
  still pin a release.)
- **`draugr doctor` now reports your Draugr version vs the latest available** (best-effort,
  short timeout), nudging `self-update` when you're behind. Opt out with `--offline` or
  `DRAUGR_NO_UPDATE_CHECK=1`; it never blocks or fails the command.
- **`draugr tools install` shows an install plan and confirms interactively.** It prints the
  plan first — tool, version, **category**, verification, destination — and asks for
  confirmation on a TTY (`-y` to skip, `--dry-run` to only preview); CI/pipes proceed
  automatically.
- **cosign is now installable** (`draugr tools install cosign`) — a pinned, SHA-256-verified
  utility. It's what Draugr uses to verify other tools' and its own releases' provenance, so
  making it installable lets signature verification "just work" without hunting for it. Optional:
  `doctor` reports it but never fails when absent.
- **`draugr tools list` gained a CATEGORY column** (scanner vs utility).

### Changed

- **`draugr self-update` now prompts only when interactive** (consistent with `tools install`):
  a TTY gets the prompt; CI/pipes proceed automatically. `-y` still skips it.

## [0.16.0] - 2026-07-16

### Added

- **`draugr scan -j/--jobs N`** — cap how many scan jobs run in parallel (`0` = auto, one per
  CPU; `1` = serial). Scanners like Trivy and Semgrep are themselves multi-threaded, so on a
  small or busy machine the default can oversubscribe and slow a run down — `-j` lets you dial
  it in (down on a laptop, up on a big CI runner). The run's JSON `stats` now also reports the
  effective **`concurrency`** and the **`deduped`** count (identical jobs collapsed in-run), so
  you can see the effect and tune from evidence.

## [0.15.0] - 2026-07-16

### Added

- **SLSA build provenance for releases.** Each release now publishes signed **build provenance
  attestations** for its archives and `checksums.txt` (GitHub `attest-build-provenance`), so you
  can verify *where and how* a binary was built:
  `gh attestation verify draugr_<ver>_<os>_<arch>.tar.gz --repo draugr-dev/draugr`. This is on
  top of the existing cosign-signed checksums and SBOMs.

## [0.14.0] - 2026-07-16

### Added

- **gosec as a second `sast` scanner.** The `sast` control can now run **gosec** — a
  Go-specialized static analyzer — alongside (or instead of) Semgrep. Select the scanner set
  with `controllers.sast.scanners: [semgrep, gosec]` (default `[semgrep]`); it works at the
  project level or as a per-component override, so you can enable gosec just on your Go
  components. `draugr tools install gosec` provisions a pinned, SHA-256-verified binary, and
  `draugr doctor` knows about it. gosec is Go-only (it errors on non-Go repos), which is why
  it's opt-in.

## [0.13.0] - 2026-07-15

### Changed

- **Releases now sign with the modern Sigstore bundle.** The release's `checksums.txt` is
  signed with keyless cosign into a single `checksums.txt.sigstore.json` bundle (via
  cosign-installer v4), replacing the separate `checksums.txt.sig` + `.pem` files. Verify with
  `cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp … …`.
  The self-scan, the GitHub Action, and the docs verify the new bundle; the install/quickstart
  recipes are updated accordingly.

### Added

- **`draugr tools install` now verifies upstream cosign signatures** (where the upstream
  publishes them), on top of the mandatory SHA-256 pin. For Trivy, Draugr verifies the keyless
  signature over the release's checksums file — checking the signing certificate identity and
  OIDC issuer via the `cosign` CLI, then confirming the downloaded archive is listed in the
  signed checksums — giving signed provenance, not just integrity. It degrades gracefully to
  SHA-256-only (with a note) when `cosign` isn't installed or the upstream isn't signed (e.g.
  gitleaks); if `cosign` is present but verification fails, the install aborts. Each installed
  tool reports what was verified.

## [0.12.1] - 2026-07-15

### Changed

- **Action metadata for the GitHub Marketplace.** Renamed the action to
  **Draugr Security Scan** (a Marketplace name must be unique across all actions/users/orgs)
  and shortened its description to meet the 125-character limit. No behavior or input change —
  `uses: draugr-dev/draugr@…` is unchanged.

## [0.12.0] - 2026-07-15

### Added

- **First-party GitHub Action.** Add Draugr to CI and GitHub code scanning with
  `uses: draugr-dev/draugr@vX.Y.Z` — it downloads a cosign-verified Draugr release for the
  runner, runs `draugr scan` against your Saga, and exposes the merged SARIF (`sarif` output)
  for `upload-sarif`, so findings land as one clean **Draugr** tool in the Security tab.
  Inputs cover `saga`, `version`, `fail-on`, `fail-on-priority`, `min-priority`, `cache-dir`,
  `output`, `working-directory`, and a raw-`args` escape hatch; the release signature is
  cosign-verified by default. Draugr's own self-scan now dogfoods this action.

## [0.11.0] - 2026-07-15

### Added

- **Content-addressed image caching.** A container image can now carry an immutable
  `digest:` alongside its `image:` tag in the Saga. With `--cache-dir`, results are keyed on
  the digest, so a rebuilt image pushed under the same tag re-scans immediately instead of
  serving the old result until the TTL. The `k8s-images` surveyor captures the running
  digest of each image automatically; you can also pin `digest:` by hand. When a digest is
  set, Draugr scans the digest-pinned reference (`repo:tag@sha256:…`) so the bytes scanned
  match what the result is cached under, while the readable tag is kept in the report.

### Changed

- **Faster high-volume scanning.** Before the concurrent scan fan-out, Draugr now pre-warms
  shared scanner state once — for Trivy, it downloads the vulnerability DB a single time
  (`trivy image --download-db-only`) instead of every parallel process cold-starting it. And
  identical jobs within a run (the same scanner + target + config, e.g. one image referenced by
  two components) are de-duplicated so the target is scanned once and the result shared. Run
  stats now report `deduped` alongside `scans` and `cacheHits`.

## [0.10.0] - 2026-07-15

### Changed

- **SARIF now reports as a single `Draugr` tool.** Draugr is an orchestrator that normalizes many
  scanners into one report, so its SARIF is emitted as one `Draugr` run instead of one run per
  underlying scanner — each finding keeps its originating scanner in `properties.tool`. In GitHub
  code scanning this shows a single "Draugr" analysis/check rather than separate "Trivy",
  "Semgrep OSS", … checks, with per-finding attribution preserved.
- **Result cache now invalidates when Trivy's vulnerability DB updates.** With `--cache-dir`,
  cached image/dependency/IaC results were keyed without the scanner or DB version, so a new
  Trivy DB (new CVEs) wouldn't trigger a re-scan until the TTL expired. The cache key now folds
  in the Trivy tool and vuln-DB version, so a DB refresh correctly invalidates stale results.
  The version is probed once per run and only when caching is enabled (no overhead otherwise).

## [0.9.0] - 2026-07-14

### Added

- **`headers` control** — a native HTTP security-header analyzer (no external tool) for a
  component's `hosts:`. Fetches each endpoint and checks it against the OWASP Secure Headers
  guidance — HSTS, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, wildcard CORS, and `Server`/`X-Powered-By`
  disclosure — normalized to SARIF like every other control. The checklist is tuned by each
  host's `type` (`browser` — the default — vs. `api`), so browser-only headers aren't flagged
  on APIs. The host `type` values are now **`browser` | `api`** (was `web` | `api`).

## [0.8.0] - 2026-07-14

### Added

- **`draugr tools install`** — fetch pinned, **checksum-verified** scanner binaries (`trivy`,
  `gitleaks`) into a Draugr-managed `~/.draugr/bin`, which Draugr adds to `PATH` automatically so
  `scan` and `doctor` use them with no shell config. Opt-in and explicit — nothing is ever
  downloaded during a scan, and every download is verified against a SHA-256 recorded in Draugr
  before it's placed on disk. Semgrep (a Python package) prints its pinned `pipx` command instead.
  `draugr tools list` shows what's pinned and what's installed.

## [0.7.0] - 2026-07-14

### Added

- **`draugr doctor`** — a preflight that reports which external scanner tools are present,
  missing, or of what version, with an install hint for each, so a missing tool is caught up
  front instead of failing mid-scan. Given a Saga it validates the descriptor and checks only
  the tools its enabled controls need (plus `git` for repo scans); `--json` for CI. Exits
  non-zero when the descriptor is invalid or a required tool is missing, so it gates a
  pipeline: `draugr doctor saga.yaml && draugr scan saga.yaml`. It only reports — it never
  downloads anything.
- **`draugr validate <saga.yaml>`** — check a Saga against the schema without running any
  scanners. Fast and dependency-free, for a pre-commit hook, CI lint step, or editor.
- **Exploitability enrichment** — `draugr scan --kev <file>` escalates any finding whose CVE
  is on the CISA Known Exploited Vulnerabilities catalog to critical, and `--epss <file>`
  (with `--epss-threshold`) bumps CVEs the FIRST EPSS model predicts are likely to be
  exploited. Both are optional and offline (bring your own downloaded feed), so priority
  reflects real-world exploitability, not just CVSS.
- The **`k8s-images` surveyor now proposes a component's `exposure`** from namespace topology
  when surveying a specific namespace — an Ingress or externally-reachable Service →
  `public`, a NetworkPolicy → `restricted`, otherwise `internal`. It's a suggestion to review
  (authentication can't be inferred; downgrade to `authenticated` where appropriate).

### Changed

- **Clearer descriptor errors.** When `scan`, `classify`, or `survey` hit an invalid Saga they
  now say which file is bad, list every problem at once, and point you at
  `draugr validate <file>` — instead of a bare, context-free validation message.

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

[Unreleased]: https://github.com/draugr-dev/draugr/compare/v0.25.0...HEAD
[0.25.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.25.0
[0.24.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.24.1
[0.24.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.24.0
[0.23.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.23.0
[0.22.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.22.0
[0.21.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.21.0
[0.20.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.20.0
[0.19.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.19.0
[0.18.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.18.0
[0.17.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.17.0
[0.16.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.16.0
[0.15.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.15.0
[0.14.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.14.0
[0.13.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.13.0
[0.12.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.12.1
[0.12.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.12.0
[0.11.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.11.0
[0.10.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.10.0
[0.9.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.9.0
[0.8.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.8.0
[0.7.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.7.0
[0.6.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.6.0
[0.5.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.5.0
[0.4.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.4.0
[0.3.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.3.0
[0.2.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.2.0
[0.1.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.1.0
