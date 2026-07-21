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
      - uses: draugr-dev/draugr@v0.27.0
        with:
          saga: draugr.saga.yaml
          tools: true
          fail-on-new: error            # gate only on findings this PR introduces
```

See the [GitHub Action guide](github-action.md) for all inputs and modes. The rest of this page
covers running `draugr diff` directly — for other CI systems, or to understand what the action
does under the hood.

## Produce the two SARIF files

`diff` consumes the `results.sarif` files that [`draugr scan -o`](../reference/cli.md#draugr-scan-sagayaml)
writes (SARIF is the complete, structured result set). A typical setup scans `main` on push and
stores `results.sarif` as an artifact, then scans the PR:

```bash
draugr scan draugr.saga.yaml -o base/    # on the base branch (store as an artifact)
draugr scan draugr.saga.yaml -o head/    # on the PR head
```

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

`--publish` posts the diff as a **sticky** pull-request comment via the `github-pr-comment`
publisher (updated in place on each push). It uses `$GITHUB_TOKEN` in CI and no-ops off a PR:

```bash
draugr diff base/results.sarif head/results.sarif --publish
```

See the [CLI reference](../reference/cli.md#draugr-diff-basesarif-headsarif) for every `diff`
flag, and [reports & publishers](reports-and-publishers.md) for the `github-pr-comment`
publisher.
