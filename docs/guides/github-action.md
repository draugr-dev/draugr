---
title: Use in CI with the GitHub Action
description: Add Draugr to GitHub Actions with the first-party action, and its full input list.
section: Guides
order: 10
---

# Use in CI (GitHub Actions)

Add Draugr to a repository's CI with the first-party **`draugr-dev/draugr`** action. It downloads a
cosign-verified Draugr release, provisions the scanners, and, with its default **`mode: auto`**,
does the right thing per event from **one** workflow and **one** Saga:

- on a **pull request**, it scans the PR's base and head, posts **one sticky new/fixed
  comment**, and fails on a finding the change adds at or above `fail-on-new`. The Saga's
  publishers are suppressed, so it never double-posts alongside a code scanning "GitHub Advanced
  Security" comment;
- on a **push**, it runs a full scan and fails on a finding at or above `fail-on`, `P1` by
  default. The workflow's last step uploads the findings to GitHub **code scanning** (the Security
  tab).

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  pull-requests: write          # the pull-request comment
  security-events: write        # the Security tab, on a push
jobs:
  draugr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # the comparison needs the base commit
      - id: draugr
        uses: draugr-dev/draugr@v0   # pin @vX.Y.Z for reproducible CI
        with:
          saga: draugr.saga.yaml
          tools: true             # provision the scanners the controls need
          fail-on-new: P1         # fail a pull request on a new P1 finding
      - if: always() && github.event_name == 'push'   # even when the gate fails
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.draugr.outputs.sarif }}
```

This is [`examples/github-actions.yml`](../../examples/github-actions.yml), and it works with the
descriptor `draugr init` writes. `fail-on-new` is set in the workflow because `draugr init` writes
no [`config.gate.failOnNew`](../reference/saga-schema.md#configgate), and a diff with no threshold
fails on nothing. A threshold in the workflow also stands when a pull request edits the descriptor
it is judged with. Code scanning is in every public repository, and in a private one
with GitHub Advanced Security; without it, delete the last step. To have the Saga's `github`
publisher upload instead, which also dismisses the alert for a finding accepted in Draugr, see
[code scanning](code-scanning.md).

**Versioning.** `@v0` is a moving major tag that always points at the newest `v0.x` release, so
you get updates without editing the ref. For fully reproducible CI, pin an exact release instead
(`draugr-dev/draugr@v0.29.0`) and bump it deliberately. (Pre-1.0, a minor bump can be breaking, so
`@v0` means "latest, possibly-breaking".)

The scanners each control needs (Trivy, Gitleaks, Semgrep, …) still have to be on the runner:
set `tools: true` to let Draugr provision them, install them alongside (e.g.
`aquasecurity/setup-trivy`), or gate their presence with `draugr doctor`.

`doctor` also reports any surface the descriptor declares that no enabled control looks at, the
scan that passes having never opened your images. On a descriptor meant to be complete, `draugr
doctor saga.yaml --fail-on-uncovered` makes that a failing step instead of a note nobody reads.

To scan an image before pushing it, see [Scanning an image before it is pushed](../../internal/controllers/images.md#scanning-an-image-before-it-is-pushed).

## Modes

| `mode` | On | What it does | Needs |
|---|---|---|---|
| `auto` (default) | any | `diff` on `pull_request`, `scan` otherwise | both permissions below |
| `scan` | push / schedule | full scan; the Saga's publishers deliver results (e.g. `github` → code scanning) | `security-events: write` |
| `diff` | pull request, merge queue | scan base + head, post one sticky new/fixed comment (publishers suppressed). On a pull request, the base is the commit the pull request's merge is built on. On `merge_group`: base is the commit the queue built the entry on, no comment | `pull-requests: write`, `fetch-depth: 0` |

**In a merge queue**, `auto` picks `scan` for a `merge_group` event, which gates the entry on
everything in the tree, findings already on `main` included. To gate an entry on the findings it
adds, as `diff` gates its pull request, choose `diff` on `merge_group`.
[`examples/github-actions-merge-queue.yml`](../../examples/github-actions-merge-queue.yml) is the
workflow above with a `merge_group` trigger and that `mode`:

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:
  merge_group:
    types: [checks_requested]
permissions:
  contents: read
  pull-requests: write          # the pull-request comment
  security-events: write        # the Security tab, on a push
jobs:
  draugr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # the comparison needs the base commit
      - id: draugr
        uses: draugr-dev/draugr@v0   # pin @vX.Y.Z for reproducible CI
        with:
          saga: draugr.saga.yaml
          tools: true             # provision the scanners the controls need
          mode: ${{ github.event_name == 'merge_group' && 'diff' || 'auto' }}
          fail-on-new: P1         # fail a pull request or a queue entry on a new P1 finding
      - if: always() && github.event_name == 'push'   # even when the gate fails
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.draugr.outputs.sarif }}
```

A pull request that adds the repository's first descriptor has none at its base. Diff mode then
compares the head against no findings, so every finding is new and `fail-on-new` gates on them. A
pull request with no descriptor at the head fails with a message saying so, because there is nothing
to scan.

A pull request from a fork runs with a read-only `GITHUB_TOKEN`, whatever the workflow's
`permissions:` grant, so diff mode cannot post the comment. The step states that in a notice, writes
the diff to the job summary and the log, and passes or fails on the gate alone.

Prefer the single **`auto`** workflow above. It keeps code-scanning uploads off PRs, which is what
avoids a second, overlapping PR comment. See [gate PRs on new findings](pr-diff.md) and [code
scanning](code-scanning.md) for each mode in depth.

## Action inputs

| Input | Default | Description |
|---|---|---|
| `saga` |, (required) | Path to the Saga descriptor to scan. |
| `mode` | `auto` | `auto` (diff on PRs, scan otherwise), `scan`, or `diff`. |
| `version` | `latest` | Draugr release to use (with or without a leading `v`). Pin for reproducibility. |
| `fail-on` | `P1` | (scan) What fails the gate: a priority band (`P1`–`P4`), which folds in what the descriptor declares about the component, or a severity (`critical`, `high`, `medium`, `low`). |
| `fail-on-priority` | | Deprecated: write the band in `fail-on`, which takes either vocabulary. |
| `fail-on-new` | | (diff) Fail on a **new** finding at or above this: a priority band (`P1`-`P4`) or a severity. Empty applies the descriptor's [`config.gate.failOnNew`](../reference/saga-schema.md#configgate), which a release without `draugr diff --saga` ignores. |
| `fail-on-new-priority` | | Deprecated: write the band in `fail-on-new`, which takes either vocabulary. |
| `diff-view` | `findings` | (diff) What the pull-request comment says. `findings` is a row per finding; `actions` groups them into the things somebody would do, so six advisories in one library are one upgrade. |
| `min-priority` |, | List findings at or above this band in the console output. |
| `cache-dir` |, | Enable content-hash caching in this directory (relative to `working-directory`). |
| `output` | `draugr-out` | Directory for `report.json`, `results.sarif` and any SBOMs (relative to `working-directory`). Written in both scan and diff mode. |
| `working-directory` | `.` | Directory to run Draugr in. |
| `args` |, | Extra raw arguments appended to `draugr scan` (escape hatch). |
| `verify` | `true` | Cosign-verify the release signature (the checksum is always verified). A failed cosign installation is tried once more before the job fails. |
| `tools` | `false` | Provision the external scanners with `draugr tools install --saga`, which fetches the ones this descriptor's controls will run and leaves the rest. Set `true` when the runner doesn't already have them. |
| `feeds` | `false` | Fetch the exploitability datasets (KEV, EPSS) into the runner's cache before scanning. Set `true` when the Saga's `config.exploitability` reads them with `cache`. |

### Ranking by real-world exploitability

Set `feeds: true` when the descriptor asks for KEV or EPSS from the cache:

```yaml
- uses: draugr-dev/draugr@v0
  with:
    saga: draugr.saga.yaml
    tools: true
    feeds: true          # draugr feeds update, before the scan
    fail-on: P1
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

A fetch that fails **keeps the cached copy** and reports how old it is. What this guards against is
a scan ranking everything as though nothing were exploited, and a cached catalog does not do that:
it ranks on data of a known age, which the report then carries. With nothing cached there is no
answer to keep, and the step fails. So a pipeline is not blocked by an upstream outage it can
already answer around. See
[`config.exploitability`](../reference/saga-schema.md#configexploitability).

### What code scanning receives

On a pull request the action runs a diff, and by default the SARIF it hands to code scanning
carries **only the findings the branch introduced** (`code-scanning: new`). An upload of the whole
repository annotates a reviewer with hundreds of findings they did not cause, and the ones they did
are indistinguishable among them, which is how a review surface stops being read. Set
`code-scanning: all` for the previous behavior. On a push there is nothing to diff against, so the
upload is always the complete scan.

`code-scanning-min-priority: P1` narrows it further, to what is urgent. It applies to the diff, not
to the scans the diff was computed from, a diff taken from filtered inputs would read every finding
the filter removed as *fixed*.

```yaml
- uses: draugr-dev/draugr@v0
  id: draugr
  with:
    saga: draugr.saga.yaml
    code-scanning: new             # default. What this PR is answerable for
    code-scanning-min-priority: P1 # and only what is urgent
```

A narrowed SARIF records the band inside itself, so nothing reading it later mistakes it for a
complete scan. The complete report is still written to `output`, and `outputs.report` still names
it, only `outputs.sarif` follows the setting.

Outputs: **`sarif`** (path to the SARIF to upload: the new-findings one in diff mode, otherwise
`code-scanning.sarif`, the complete scan in the form code scanning accepts) and
**`report`** (path to `report.json`, always complete). Both point inside `output` and are written
on pull requests too, so an `if: always()` upload step finds them whichever mode the action ran in.

## Server

The [`draugr-api` publisher](reports-and-publishers.md#a-server-that-keeps-your-runs) sends each run
to a Draugr server, which keeps it with the runs before it. Without a server, the scan still decides
the verdict and the gate.

Create an ingest token for the project on your server. It is write-only and scoped to that project.

[Publish runs to a Draugr server](publish-to-a-draugr-server.md) goes from creating the token to the
first run in the console. The hosted server, [app.draugr.dev](https://app.draugr.dev), takes sign-ups
by invitation for now, and you can [ask for one](https://draugr.dev/contact/?about=early-access). A
server you run yourself works the same way at its own address.

Store it as an encrypted secret named `DRAUGR_API_TOKEN`, under *Settings → Secrets and variables →
Actions*, and give it to the action's step in `env:` with the server's address. The action has no
input for either, and the step's environment reaches the scan.

```yaml
- uses: draugr-dev/draugr@v0
  with:
    saga: draugr.saga.yaml
  env:
    DRAUGR_API_URL: https://draugr.acme.example
    DRAUGR_API_TOKEN: ${{ secrets.DRAUGR_API_TOKEN }}
```

The action publishes only in `scan` mode, which `auto` picks on a push. A pull request runs `diff`
mode, which scans with `--no-publish` and sends nothing.

Add the publisher to the descriptor, beside any it already has:

```yaml
# draugr.saga.yaml
config:
  publishers:
    - kind: draugr-api
```

## Without the action

If you already have `draugr` on the runner (e.g. `draugr tools install`, or a self-hosted image),
run it directly. The exit code is the gate:

```yaml
- name: Draugr scan
  run: draugr scan draugr.saga.yaml -o draugr-out --report json,sarif,code-scanning
- name: Upload SARIF to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: draugr-out/code-scanning.sarif
```

Upload `code-scanning.sarif` rather than `results.sarif`: code scanning refuses a whole upload over a
finding located on an image or a host, and this file leaves those findings without a location. It
also lists a flaw two scanners found once, where `results.sarif` keeps both and code scanning would
open two alerts. See [findings with no file](code-scanning.md#findings-with-no-file) and [a flaw two
scanners found](code-scanning.md#a-flaw-two-scanners-found).

See the [CLI reference](../reference/cli.md#draugr-scan-sagayaml--dir) for every `scan` flag.
