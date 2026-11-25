---
title: Publish to GitHub code scanning
description: Upload Draugr's SARIF to the Security tab with the native github publisher.
section: Guides
order: 20
---

# Publish to GitHub code scanning

Draugr can upload its merged SARIF straight to GitHub **code scanning** (the Security tab) with the
native **`github`** publisher, no separate `upload-sarif` step. Code scanning is free for public
repos; private repos need GitHub Advanced Security.

> **On GitLab?** There is no upload: GitLab reads its own schema from build artifacts rather than
> SARIF, so the equivalent is a set of report formats and a template that collects them. See
> [use in CI with GitLab](gitlab-ci.md).

## 1. Declare the publisher in your Saga

The `github` publisher renders the `sarif` report for itself, so `kind: github` is the whole of it.
It never stores a secret in the descriptor, repo/commit/ref default from the GitHub Actions
environment, and the token comes from `$GITHUB_TOKEN`. It no-ops outside Actions, so the same Saga
still runs locally.

```yaml
config:
  publishers:
    - kind: github         # repo/commit/ref default to the GitHub Actions env
      # repo: owner/name   # optional overrides ($GITHUB_REPOSITORY / $GITHUB_SHA / $GITHUB_REF)
      # ref: refs/heads/main
      # tokenEnv: GITHUB_TOKEN   # the token is read from this env var, never the Saga
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
    saga: draugr.saga.yaml
    code-scanning: new   # the default; `all` uploads every finding
```

**What is urgent.** A band narrows it further, either per workflow or in the descriptor beside the
rest of your policy:

```yaml
config:
  publishers:
    - kind: github
      reports:
        - format: sarif
          minPriority: P1    # this report only; the JSON beside it stays complete
```

### A descriptor that describes more than one repository

A component may hold several repositories, and a [fragment](saga-fragments.md) may contribute one
from another project. Their findings carry paths relative to **their own** repository, so uploading
them here would annotate a same-named file in this one, a squiggle on a line that does not have that
problem.

The Action drops them from the upload automatically. It is not a setting, because there is no case
where annotating another repository's finding on this checkout is what you want. They stay in the
scan, in the artifacts and in the pull-request comment, where a regression in a fragment-contributed
repository is real news a reviewer should see. Findings that belong to no repository, an image's, a
host's, are unaffected, because they were never anchored to a checkout.

### What narrowing does to existing alerts

**Code scanning resolves any alert missing from an upload as fixed**, within the ref and category
that upload belongs to. Both halves matter, and the second is what makes narrowing a pull request
safe.

A pull-request run uploads against the **pull request's own ref**, not your default branch. Its
alerts are the ones shown on that pull request, and narrowing them changes nothing about
`main`: measured on a repository with 96 open alerts on `main`, a PR upload carrying zero findings
created an analysis on `refs/pull/N/merge` and left all 96 open.

So on a pull request, narrowing costs you nothing you were relying on. On a default branch it would,
an upload narrowed to `P1` there resolves the P2–P4 alerts, and they are the ones nobody is looking
at but somebody may still need. That is why a push is never narrowed: there is nothing to diff
against, so it uploads the complete scan.

A narrowed SARIF records the band it was narrowed to, so nothing reading it later, including
[`draugr diff`](pr-diff.md), which reads a missing finding as a fixed one, mistakes it for a
complete scan.

### Accepted findings

A finding accepted in Draugr, by `config.exclude`, an inline `#nosec` or a VEX statement, is
dismissed in code scanning as **won't fix**, with the reason as the comment. A `config.exclude`
entry's comment also names its file and line, `(draugr.saga.yaml:14)`, where the line's git history
records who wrote it.
Code scanning does not read the SARIF `suppressions` the report carries, so the publisher sets each
alert itself once GitHub has processed the upload.

- An alert Draugr dismissed is reopened when its finding is no longer accepted, such as when an
  exclusion expires.
- An alert a person dismissed stays as they left it.
- Findings of one rule on one line, such as a vulnerability in two packages of one image, are told
  apart by their message, which names the package. An alert that may stand for more than one of them
  stays open until every one is accepted.
- The publish waits up to five minutes for GitHub to process the upload. Past that, or when GitHub
  refuses a dismissal, the publish fails and names what was not updated. Re-run it once the token
  has `security-events: write` or GitHub has finished processing.

The token needs no permission beyond the `security-events: write` the upload already uses. An upload
made with `github/codeql-action/upload-sarif` instead of the publisher leaves accepted findings
open.

### A flaw two scanners found

A flaw two scanners found, such as a CVE Trivy and Grype both report, is one alert. The publisher,
`code-scanning.sarif` and `draugr diff --format sarif` each hold it once, as the finding the gate
counts, and that result's `correlation.alsoFoundBy` property names the other scanner and what it
called the flaw. `results.sarif` keeps both scanners' results.

### Findings with no file

A finding on a container image, a host or a cluster is about something that is not a file in the
repository, and Draugr locates it by the thing itself: `python:3.8-slim`, `https://shop.example.com/`.
Code scanning reads every location as a file, refuses a URI with a scheme it does not know, and reads
`python:3.8-slim` as one with the scheme `python`. One such location costs the whole upload, the
findings on files included.

So what goes to code scanning holds every location to a path in the repository or a `file:` URI:

- A finding on an image appears on the line that declares the image: the `image:` line in the
  descriptor, or in the fragment that declares it. That is the line you change to move to a newer
  image. The image reference stays in the result's `image` property.
- Any other such finding goes up with no location. Its rule, message and priority go up with it, and
  its reference moves to `draugr/location`. So does a finding on an image no file in the repository
  declares: one a survey found, one a fragment from another repository declares, or one in a
  descriptor outside the repository Draugr runs in.
- The publish says how many findings went up with no location. GitHub's
  [SARIF documentation](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
  says code scanning needs a location to display a result, so these findings are not in the Security
  tab. `report.json`, `results.sarif` and the console list them.
- `results.sarif` keeps the image reference as the finding's location, because `draugr diff` and
  `draugr explain` read a finding's identity from it.

For example, with this descriptor at the root of the repository:

```yaml
components:
  - name: api
    images:
      - image: python:3.8-slim
```

a vulnerable package in `python:3.8-slim` is an alert on `draugr.saga.yaml`, line 4.

To upload with `github/codeql-action/upload-sarif` instead of the publisher, upload
`code-scanning.sarif`, which `--report code-scanning` writes beside `results.sarif`:

```bash
draugr scan draugr.saga.yaml -o draugr-out --report json,sarif,code-scanning
```

The [GitHub Action](github-action.md) asks for it, and its `sarif` output names it. `draugr diff
--format sarif`, the new findings the Action uploads on a pull request, takes the same form, and
places a new finding on an image on a line of the descriptor `--saga` names, or of the one in the
working directory.

A rejected upload fails the publish, and the Action prints it as an error annotation on the run, so
a workflow that lets the scan step continue on error still shows it.

### Caveats

The uploaded file carries the run's caveats and scan errors as SARIF
[notifications](../reference/report-schema.md#notifications). GitHub's documentation does not say
code scanning displays them, so a clean Security tab does not show that the run read everything.
Every caveat is in `report.json`, the HTML and markdown reports, and the console with `--top 0`.

### Two products in one repository

The category an upload belongs to is what separates one analysis of a commit from another, and
Draugr sets it from the descriptor. Scan `azure.saga.yaml` and `gcp.saga.yaml` over the same
commit and each product keeps its own alerts; without a category the second upload would replace
the first, and both runs would report success.

It is written into the SARIF as `runs[].automationDetails.id`, so it travels with the file and
applies whether Draugr uploads it or `github/codeql-action/upload-sarif` does. The upload endpoint
has no category of its own to correct it with. The new findings a pull request uploads, from
`draugr diff --format sarif`, carry the category of the scan they came from, so code scanning
compares them with that product's analysis on the branch the pull request merges into.

| The descriptor | What the run covered | The category |
|---|---|---|
| `project: acme-azure` | all of it | `acme-azure` |
| `project: acme-gcp` | all of it | `acme-gcp` |
| `project: acme-azure` | `--components web --controls sca` | `acme-azure/components:web/controls:sca` |

A matrix leg is its own category for the same reason a product is, so splitting a scan across jobs
by component or by control does not leave each job erasing the last one's alerts.

The category comes from what was asked for rather than from what was found, so it is the same on
every push of the same product, and that is what lets code scanning close an alert when the
finding behind it goes away. Vary the narrowing between pushes of one product and each variant
gets its own category, which leaves the old alerts open forever and opens the new ones from
scratch.

See [`examples/publishing.saga.yaml`](../../examples/publishing.saga.yaml) for a fuller,
multi-format, multi-publisher Saga.

## 2. Run it from a workflow

The action forwards `GITHUB_TOKEN` to the scan, and the job grants `security-events: write` so
the upload is allowed. This is
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
          tools: true                     # provision the scanners the controls need
          fail-on-new: P1                 # fail a pull request on a new P1 finding
```

A push fails on any `P1` finding, the action's default. `fail-on-new` gates a pull request on the
findings it adds, and is set here because `draugr init` writes no
[`config.gate.failOnNew`](../reference/saga-schema.md#configgate): a diff with no threshold fails
on nothing. [`examples/github-actions.yml`](../../examples/github-actions.yml) is the same
workflow for a descriptor with no `github` publisher, uploading with an `upload-sarif` step.

Because the publisher lives in the Saga, findings are uploaded even on a FAIL verdict, so you
always get evidence in the Security tab. Draugr dogfoods this itself in
[`.draugr/self.saga.yaml`](../../.draugr/self.saga.yaml) plus its self-scan workflow.

> **Why the same workflow handles PRs without a duplicate comment.** With the action's default
> `mode: auto`, code-scanning upload happens on **push**, while **pull requests** get Draugr's
> own sticky diff comment instead (publishers suppressed). If you upload to code scanning **on
> PRs too**, GitHub's own "GitHub Advanced Security" bot also comments, so you'd see two
> overlapping comments. Keeping the upload to push (the default) avoids that. See
> [gate PRs on new findings](pr-diff.md).

For the plain `upload-sarif` alternative (no publisher in the Saga), see the
[GitHub Action guide](github-action.md); for the full list of report formats and publishers,
see [reports & publishers](reports-and-publishers.md). To get the same findings inline in
your editor rather than on a pull request, see
[see findings in your editor](findings-in-your-editor.md).
