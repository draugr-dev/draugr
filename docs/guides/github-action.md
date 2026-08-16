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
      - uses: draugr-dev/draugr@v0   # latest v0.x; pin @vX.Y.Z for reproducible CI (installs Draugr for you)
        with:
          saga: draugr.saga.yaml
          tools: true             # provision the scanners the controls need
          # fail-on: high         # (scan/push) gate the build
          # fail-on-new: high     # (diff/PR)   gate only on findings this PR introduces
```

**Versioning.** `@v0` is a moving major tag that always points at the newest `v0.x` release, so
you get updates without editing the ref. For fully reproducible CI, pin an exact release instead
(`draugr-dev/draugr@v0.29.0`) and bump it deliberately. (Pre-1.0, a minor bump can be breaking, so
`@v0` means "latest, possibly-breaking".)

The scanners each control needs (Trivy, Gitleaks, Semgrep, …) still have to be on the runner:
set `tools: true` to let Draugr provision them, install them alongside (e.g.
`aquasecurity/setup-trivy`), or gate their presence with `draugr doctor`.

`doctor` also reports any surface the descriptor declares that no enabled control looks at — the
scan that passes having never opened your images. On a descriptor meant to be complete,
`draugr doctor saga.yaml --fail-on-uncovered` makes that a failing step instead of a note nobody
reads.

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
| `fail-on` | `high` | (scan) Severity that fails the gate: `critical`, `high`, `medium`, `low`. |
| `fail-on-priority` | — | (scan) Also fail on any finding at or above this priority band (`P1`–`P4`). |
| `fail-on-new` | — | (diff) Fail on a **new** finding at or above this severity. |
| `fail-on-new-priority` | — | (diff) Fail on a **new** finding at or above this priority band. |
| `min-priority` | — | List findings at or above this band in the console output. |
| `cache-dir` | — | Enable content-hash caching in this directory (relative to `working-directory`). |
| `output` | `draugr-out` | Directory for `report.json`, `results.sarif` and any SBOMs (relative to `working-directory`). Written in both scan and diff mode. |
| `working-directory` | `.` | Directory to run Draugr in. |
| `args` | — | Extra raw arguments appended to `draugr scan` (escape hatch). |
| `verify` | `true` | Cosign-verify the release signature (the checksum is always verified). |
| `tools` | `false` | Provision the external scanners (Trivy, Gitleaks, gosec, Semgrep) with `draugr tools install` before scanning. Set `true` when the runner doesn't already have them. |
| `feeds` | `false` | Fetch the exploitability datasets (KEV, EPSS) into the runner's cache before scanning. Set `true` when the Saga's `config.exploitability` reads them with `cache`. |

### Ranking by real-world exploitability

Set `feeds: true` when the descriptor asks for KEV or EPSS from the cache:

```yaml
- uses: draugr-dev/draugr@v0
  with:
    saga: draugr.saga.yaml
    tools: true
    feeds: true          # draugr feeds update, before the scan
    fail-on-priority: P1
```

```yaml
# draugr.saga.yaml
config:
  exploitability:
    kev: cache
    epss: cache
```

**Its own step on purpose.** The scan then reads the cache and never reaches the network, so the
gate stays reproducible, and a feed outage surfaces at the fetch rather than inside a scan.

A fetch that fails **keeps the cached copy** and reports how old it is — what this guards against
is a scan ranking everything as though nothing were exploited, and a cached catalogue does not do
that: it ranks on data of a known age, which the report then carries. With nothing cached there is
no answer to keep, and the step fails. So a pipeline is not blocked by an upstream outage it can
already answer around. See
[`config.exploitability`](../reference/saga-schema.md#configexploitability).

### What code scanning receives

On a pull request the action runs a diff, and by default the SARIF it hands to code scanning
carries **only the findings the branch introduced** (`code-scanning: new`). An upload of the whole
repository annotates a reviewer with hundreds of findings they did not cause, and the ones they did
are indistinguishable among them — which is how a review surface stops being read. Set
`code-scanning: all` for the previous behaviour. On a push there is nothing to diff against, so the
upload is always the complete scan.

`code-scanning-min-priority: P1` narrows it further, to what is urgent. It applies to the diff, not
to the scans the diff was computed from — a diff taken from filtered inputs would read every
finding the filter removed as *fixed*.

```yaml
- uses: draugr-dev/draugr@v0
  id: draugr
  with:
    code-scanning: new             # default — what this PR is answerable for
    code-scanning-min-priority: P1 # and only what is urgent
```

A narrowed SARIF records the band inside itself, so nothing reading it later mistakes it for a
complete scan. The complete report is still written to `output`, and `outputs.report` still names
it — only `outputs.sarif` follows the setting.

Outputs: **`sarif`** (path to the SARIF to upload — the new-findings one in diff mode) and
**`report`** (path to `report.json`, always complete). Both
point inside `output` and are written on pull requests too, so an `if: always()` upload step
finds them whichever mode the action ran in.

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

See the [CLI reference](../reference/cli.md#draugr-scan-sagayaml--dir) for every `scan` flag.
