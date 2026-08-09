---
title: Gate PRs on new findings
description: Use draugr diff to gate a PR on the findings it introduces and post a sticky comment.
section: Guides
order: 30
---

# Gate PRs on new findings

`draugr diff` compares two scans and classifies every finding as **new**, **fixed**, or
**unchanged** — the security delta of a change, typically a PR's head vs its base branch. This
lets you gate a PR only on the findings it *introduces*, not the pre-existing backlog, so the
gate stays adoptable where a whole-backlog gate would block every PR.

## How it works

**Draugr stores nothing.** There is no baseline kept on a server, no history of previous runs, no
"last known state of `main`". `draugr diff` takes two SARIF files that you hand it and compares
them:

```bash
draugr diff base/results.sarif head/results.sarif
```

So "the result from `main`" is a file **you produced by scanning `main`** — in the same pipeline
run, or stored as an artifact by the last build of `main`. Nothing is fetched.

That is deliberate. A CLI running in someone's pipeline should not be a service with memory of
previous runs, because then the answer depends on state you cannot see and cannot reproduce. Two
files in, one answer out, the same answer forever.

### What counts as "the same finding"

Findings are matched on **tool + rule + file + message** — deliberately *not* on the line number
or the severity. Code moves, and a finding that slid down twelve lines is not a fix plus a new
problem. A CVE that gets re-scored is still the same CVE.

Whatever is in `head` and not in `base` is **new**; in `base` and not in `head` is **fixed**; in
both is **unchanged**.

### Where the base comes from

Three ways, in increasing order of effort:

| | How | Cost |
|---|---|---|
| **The GitHub Action** | `mode: auto` scans both sides for you | nothing to wire |
| **Scan both in one job** | check out the base, scan, check out head, scan | two scans per pull request |
| **A stored artifact** | the last build of `main` published its `results.sarif` | one scan per pull request, but the base can be stale |

The middle one works on any CI system and is the one to start with. The artifact approach is
faster, at the cost of a base that describes whatever commit last ran rather than the actual merge
base.

## In CI: let the action do it

On GitHub, you don't wire this up by hand. The first-party action's default **`mode: auto`**
runs a diff on `pull_request` events — it scans the base and head for you and posts one sticky
new/fixed comment — and a full scan on push. One workflow, one Saga:

```yaml
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # push: code scanning
  pull-requests: write     # PR: the diff comment
jobs:
  draugr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # diff needs the base commit
      - uses: draugr-dev/draugr@v0
        with:
          saga: draugr.saga.yaml
          tools: true
          fail-on-new: error            # gate only on findings this PR introduces
```

See the [GitHub Action guide](github-action.md) for all inputs and modes. The rest of this page
covers running `draugr diff` directly — for other CI systems, or to understand what the action
does under the hood.

## Produce the two SARIF files

`diff` consumes the `results.sarif` files that [`draugr scan -o`](../reference/cli.md#draugr-scan-sagayaml--dir)
writes (SARIF is the complete, structured result set). A typical setup scans `main` on push and
stores `results.sarif` as an artifact, then scans the PR:

```bash
draugr scan draugr.saga.yaml --no-gate -o base/    # on the base branch
draugr scan draugr.saga.yaml --no-gate -o head/    # on the PR head
```

**`--no-gate` on both.** These two scans exist to produce reports; the diff is the gate. Without
it a `FAIL` verdict on the base — which any repository with a backlog will produce — exits
non-zero and takes the whole step with it under `set -e`. It suppresses the verdict's exit code
only: a scan that could not run still fails, so a missing report never reaches the diff disguised
as "no new findings".

For a complete pipeline, see [Azure Pipelines](azure-pipelines.md#gating-on-new-findings); on GitHub
the action's `mode: auto` does all of this for you.

Each scan clones the repository before reading it, so a `results.sarif` always describes a
**committed revision** — which is what makes the two comparable, and what a reader needs in order
to reproduce either side. It also means the pair above only differs if the two scans ran against
different commits: iterating locally with `scan → edit → scan` compares `HEAD` with itself and
reports no change. Commit between the two, or set `revision` on the repository to name each
revision explicitly. See
[URLs and paths](../reference/saga-schema.md#where-a-repository-comes-from-urls-and-paths).

## Diff and gate

```bash
draugr diff base/results.sarif head/results.sarif                     # console delta
draugr diff base/results.sarif head/results.sarif --format markdown   # MR comment
draugr diff base/results.sarif head/results.sarif --fail-on-new-priority P1
draugr diff base/results.sarif head/results.sarif --publish           # sticky PR comment (in CI)
```

`--fail-on-new` / `--fail-on-new-priority` fail the command (non-zero exit) only for **new**
findings at or above the given severity / priority. Findings are matched on
`(tool, rule, file, message)` — deliberately ignoring the line number (which drifts as code
moves) and the severity level (a re-scored finding is still the same issue), so
genuinely-carried-over findings aren't reported as fixed + new.

## Post the delta as a PR comment

`--publish` posts the diff as a **sticky** pull-request comment, updated in place on each push,
and no-ops off a pull request:

```bash
draugr diff base/results.sarif head/results.sarif --publish
```

It picks the publisher from the CI system it is running on — `github-pr-comment` under GitHub
Actions with `$GITHUB_TOKEN`, `azure-pr-comment` under Azure Pipelines with `$SYSTEM_ACCESSTOKEN`.
Azure needs that variable mapped into the step; see
[Azure Pipelines](azure-pipelines.md#a-sticky-comment).

The diff keeps its **own** sticky comment, separate from the one a Saga's PR-comment publisher
maintains. A pipeline can run both — the state of the branch, and what this pull request changed
— and get two comments rather than one overwriting the other.

## Severity in a diff

A diff reports the same **critical / high / medium / low** bands the scan report uses, because it
is read next to that report and the two have to agree.

Those bands are Draugr's own, normalized across every control so a dependency CVE, a leaked secret
and an IaC misconfiguration can share one ordered list — a CVSS-style score decides the band when
a scanner publishes one, and the SARIF level decides it when none is published. The `error` /
`warning` / `note` values you will see inside a `results.sarif` file are SARIF's wire vocabulary,
not a severity: SARIF has three of them, and they cannot express the difference between a 7.0 and
a 9.8.

`--fail-on-new` takes a **SARIF level** (`error` / `warning` / `note`), not a band — the same
split `--fail-on` has, and it is checked, so `--fail-on-new high` is an error rather than a gate
that quietly matches everything. To gate on the bands' underlying risk instead, use
`--fail-on-new-priority`.

Severity is still not priority. `P1`–`P4` fold in the component's declared exposure and
criticality, which is why a `high` on an internet-facing component outranks a `critical` on
something nothing can reach. See [prioritization](../concepts/prioritization.md).

See the [CLI reference](../reference/cli.md#draugr-diff-basesarif-headsarif) for every `diff`
flag, and [reports & publishers](reports-and-publishers.md) for both publishers.
