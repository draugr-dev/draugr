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
    branches: [main]
permissions:
  contents: read
  security-events: write   # required for the github publisher to upload SARIF
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Draugr scan + publish to code scanning
        uses: draugr-dev/draugr@v0     # pin a released version in real use
        with:
          saga: draugr.saga.yaml       # a Saga with a `github` publisher in config.publishers
          fail-on: error               # optional: fail the build on error-level findings
```

Because the publisher lives in the Saga, findings are uploaded even on a FAIL verdict, so you
always get evidence in the Security tab. Draugr dogfoods this itself in
[`.draugr/self.saga.yaml`](../../.draugr/self.saga.yaml) plus its self-scan workflow.

For the plain `upload-sarif` alternative (no publisher in the Saga), see the
[GitHub Action guide](github-action.md); for the full list of report formats and publishers,
see [reports & publishers](reports-and-publishers.md).
