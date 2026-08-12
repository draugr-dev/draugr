---
title: Publish to GitHub code scanning
description: Upload Draugr's SARIF to the Security tab with the native github publisher.
section: Guides
order: 20
---

# Publish to GitHub code scanning

Draugr can upload its merged SARIF straight to GitHub **code scanning** (the Security tab) with
the native **`github`** publisher — no separate `upload-sarif` step. Code scanning is free for
public repos; private repos need GitHub Advanced Security.

## 1. Declare the publisher in your Saga

The `github` publisher requires a `sarif` report in `config.reports`. It never stores a secret
in the descriptor — repo/commit/ref default from the GitHub Actions environment, and the token
comes from `$GITHUB_TOKEN`. It no-ops outside Actions, so the same Saga still runs locally.

```yaml
config:
  reports:
    - format: sarif
  publishers:
    - kind: github         # repo/commit/ref default to the GitHub Actions env
      # repo: owner/name   # optional overrides ($GITHUB_REPOSITORY / $GITHUB_SHA / $GITHUB_REF)
      # ref: refs/heads/main
      # tokenEnv: GITHUB_TOKEN   # the token is read from this env var — never the Saga
```

## Choosing what a reviewer sees

An alert on every finding in the repository is an alert on nothing: a reviewer opening a pull
request is annotated with hundreds they did not cause, and the ones they did are indistinguishable
among them. Two ways to narrow it, and they compose.

**What this change introduced.** The [GitHub Action](github-action.md) runs a diff on a pull
request and, by default, uploads only the findings the branch added:

```yaml
- uses: draugr-dev/draugr@v0
  with:
    code-scanning: new   # the default; `all` uploads every finding
```

**What is urgent.** A band narrows it further, either per workflow or in the descriptor beside the
rest of your policy:

```yaml
config:
  reports:
    - format: sarif
      minPriority: P1    # this report only; the JSON beside it stays complete
```

### What narrowing does to existing alerts

**Code scanning resolves any alert missing from an upload as fixed** — within the ref and category
that upload belongs to. Both halves matter, and the second is what makes narrowing a pull request
safe.

A pull-request run uploads against the **pull request's own ref**, not your default branch. Its
alerts are the ones shown on that pull request, and narrowing them changes nothing about
`main`: measured on a repository with 96 open alerts on `main`, a PR upload carrying zero findings
created an analysis on `refs/pull/N/merge` and left all 96 open.

So on a pull request, narrowing costs you nothing you were relying on. On a default branch it would
— an upload narrowed to `P1` there resolves the P2–P4 alerts, and they are the ones nobody is
looking at but somebody may still need. That is why a push is never narrowed: there is nothing to
diff against, so it uploads the complete scan.

A narrowed SARIF records the band it was narrowed to, so nothing reading it later — including
[`draugr diff`](pr-diff.md), which reads a missing finding as a fixed one — mistakes it for a
complete scan.

See [`examples/reporting.saga.yaml`](../../examples/reporting.saga.yaml) for a fuller,
multi-format, multi-publisher Saga.

## 2. Run it from a workflow

The action forwards `GITHUB_TOKEN` to the scan, and the job grants `security-events: write` so
the upload is allowed. This mirrors
[`examples/github-actions-code-scanning.yml`](../../examples/github-actions-code-scanning.yml):

```yaml
name: Draugr
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write   # push: the github publisher uploads SARIF
  pull-requests: write     # PR: the sticky diff comment
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # so PR diff mode can reach the base commit
      - name: Draugr scan + publish to code scanning
        uses: draugr-dev/draugr@v0   # latest v0.x; pin @vX.Y.Z for reproducible CI
        with:
          saga: draugr.saga.yaml          # a Saga with a `github` publisher in config.publishers
          tools: true
          fail-on: error                  # optional: fail the build on error-level findings
```

Because the publisher lives in the Saga, findings are uploaded even on a FAIL verdict, so you
always get evidence in the Security tab. Draugr dogfoods this itself in
[`.draugr/self.saga.yaml`](../../.draugr/self.saga.yaml) plus its self-scan workflow.

> **Why the same workflow handles PRs without a duplicate comment.** With the action's default
> `mode: auto`, code-scanning upload happens on **push**, while **pull requests** get Draugr's
> own sticky diff comment instead (publishers suppressed). If you upload to code scanning **on
> PRs too**, GitHub's own "GitHub Advanced Security" bot also comments — so you'd see two
> overlapping comments. Keeping the upload to push (the default) avoids that. See
> [gate PRs on new findings](pr-diff.md).

For the plain `upload-sarif` alternative (no publisher in the Saga), see the
[GitHub Action guide](github-action.md); for the full list of report formats and publishers,
see [reports & publishers](reports-and-publishers.md). To get the same findings inline in
your editor rather than on a pull request, see
[see findings in your editor](findings-in-your-editor.md).
