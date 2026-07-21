---
title: Use in CI with the GitHub Action
description: Add Draugr to GitHub Actions with the first-party action, and its full input list.
section: Guides
order: 10
---

# Use in CI (GitHub Actions)

Add Draugr to a repository's CI with the first-party **`draugr-dev/draugr`** action. It
downloads a cosign-verified Draugr release, provisions the scanners, and — with its default
**`mode: auto`** — does the right thing per event from **one** workflow and **one** Saga:

- on **push**, it runs a full scan and uploads the merged SARIF to GitHub **code scanning** (the
  Security tab), via the Saga's `github` publisher;
- on a **pull request**, it scans the PR's base and head and posts **one sticky new/fixed
  comment** — with the Saga's publishers suppressed, so it never double-posts alongside a code
  scanning "GitHub Advanced Security" comment.

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write        # push: upload SARIF to code scanning
  pull-requests: write          # PRs: post the sticky diff comment
jobs:
  draugr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # diff mode needs the PR's base commit
      - uses: draugr-dev/draugr@v0.27.0   # pin a release; installs Draugr for you
        with:
          saga: draugr.saga.yaml
          tools: true             # provision the scanners the controls need
          # fail-on: error        # (scan/push) gate the build
          # fail-on-new: error    # (diff/PR)   gate only on findings this PR introduces
```

The scanners each control needs (Trivy, Gitleaks, Semgrep, …) still have to be on the runner:
set `tools: true` to let Draugr provision them, install them alongside (e.g.
`aquasecurity/setup-trivy`), or gate their presence with `draugr doctor`.

## Modes

| `mode` | On | What it does | Needs |
|---|---|---|---|
| `auto` (default) | any | `diff` on `pull_request`, `scan` otherwise | both permissions below |
| `scan` | push / schedule | full scan; the Saga's publishers deliver results (e.g. `github` → code scanning) | `security-events: write` |
| `diff` | pull request | scan base + head, post one sticky new/fixed comment (publishers suppressed) | `pull-requests: write`, `fetch-depth: 0` |

Prefer the single **`auto`** workflow above — it keeps code-scanning uploads off PRs, which is
what avoids a second, overlapping PR comment. See [gate PRs on new findings](pr-diff.md) and
[code scanning](code-scanning.md) for each mode in depth.

## Action inputs

| Input | Default | Description |
|---|---|---|
| `saga` | — (required) | Path to the Saga descriptor to scan. |
| `mode` | `auto` | `auto` (diff on PRs, scan otherwise), `scan`, or `diff`. |
| `version` | `latest` | Draugr release to use (with or without a leading `v`). Pin for reproducibility. |
| `fail-on` | `error` | (scan) Severity that fails the gate: `error`, `warning`, `note`. |
| `fail-on-priority` | — | (scan) Also fail on any finding at or above this priority band (`P1`–`P4`). |
| `fail-on-new` | — | (diff) Fail on a **new** finding at or above this severity. |
| `fail-on-new-priority` | — | (diff) Fail on a **new** finding at or above this priority band. |
| `min-priority` | — | List findings at or above this band in the console output. |
| `cache-dir` | — | Enable content-hash caching in this directory (relative to `working-directory`). |
| `output` | `draugr-out` | Directory for `report.json` and `results.sarif` (relative to `working-directory`). |
| `working-directory` | `.` | Directory to run Draugr in. |
| `args` | — | Extra raw arguments appended to `draugr scan` (escape hatch). |
| `verify` | `true` | Cosign-verify the release signature (the checksum is always verified). |
| `tools` | `false` | Provision the external scanners (Trivy, Gitleaks, gosec via `draugr tools install`, Semgrep via pipx) before scanning. Set `true` when the runner doesn't already have them. |

Outputs: **`sarif`** (path to `results.sarif`) and **`report`** (path to `report.json`).

## Without the action

If you already have `draugr` on the runner (e.g. `draugr tools install`, or a self-hosted
image), run it directly — the exit code is the gate:

```yaml
- name: Draugr scan
  run: draugr scan draugr.saga.yaml -o draugr-out
- name: Upload SARIF to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: draugr-out/results.sarif
```

See the [CLI reference](../reference/cli.md#draugr-scan-sagayaml) for every `scan` flag.
