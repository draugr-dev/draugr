---
title: Use in CI with the GitHub Action
description: Add Draugr to GitHub Actions with the first-party action, and its full input list.
section: Guides
order: 10
---

# Use in CI (GitHub Actions)

Add Draugr to a repository's CI with the first-party **`draugr-dev/draugr`** action. It
downloads a cosign-verified Draugr release, runs the scan, and hands the merged SARIF to
GitHub code scanning — one clean **Draugr** tool in the Security tab.

```yaml
name: Security
on: [pull_request]
permissions:
  contents: read
  security-events: write        # upload SARIF to code scanning
jobs:
  draugr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Install the scanners the enabled controls need (Draugr orchestrates them; it doesn't
      # bundle them). Example for images/sca/iac:
      - uses: aquasecurity/setup-trivy@v0.3.1

      - id: draugr
        uses: draugr-dev/draugr@v0.16.0      # pin a release; installs Draugr for you
        with:
          saga: draugr.saga.yaml
          fail-on: warning                   # optional; default is `error`

      - if: always()                         # publish findings even when the gate fails
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.draugr.outputs.sarif }}
```

The scanners each control needs (Trivy, Gitleaks, …) still have to be on the runner — install
them alongside as above, set the action's `tools: true` input to let Draugr provision them, or
gate their presence with `draugr doctor`.

To publish findings without a separate `upload-sarif` step, use the native `github` publisher
instead — see [code scanning](code-scanning.md).

## Action inputs

| Input | Default | Description |
|---|---|---|
| `saga` | — (required) | Path to the Saga descriptor to scan. |
| `version` | `latest` | Draugr release to use (with or without a leading `v`). Pin for reproducibility. |
| `fail-on` | `error` | Severity that fails the gate: `error`, `warning`, `note`. |
| `fail-on-priority` | — | Also fail on any finding at or above this priority band (`P1`–`P4`). |
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
