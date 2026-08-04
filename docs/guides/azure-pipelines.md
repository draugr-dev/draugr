---
title: Use in CI with Azure Pipelines
description: Run Draugr in Azure DevOps, surface findings in the Tests tab, and post a sticky pull-request comment.
section: Guides
order: 15
---

# Use in CI (Azure Pipelines)

Draugr is a single binary with no Azure-specific parts, so there is no extension to install and
no service connection to create. The pipeline below is the whole integration.

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include: [main]
pr:
  branches:
    include: [main]

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
    fetchDepth: 0                 # a pull-request scan needs the base commit

  - script: |
      set -euo pipefail
      curl -fsSL https://draugr.dev/install.sh | sh
      echo "##vso[task.prependpath]$HOME/.local/bin"
      echo "##vso[task.prependpath]$HOME/.draugr/bin"
    displayName: Install Draugr

  - script: |
      set -euo pipefail
      draugr tools install -y --saga draugr.saga.yaml
    displayName: Provision scanners

  - script: |
      set -euo pipefail
      draugr scan draugr.saga.yaml --report junit,sarif -o $(Build.ArtifactStagingDirectory)
    displayName: Scan
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)   # only needed for the PR comment

  - task: PublishTestResults@2
    displayName: Publish findings to the Tests tab
    condition: succeededOrFailed()
    inputs:
      testResultsFormat: JUnit
      testResultsFiles: '$(Build.ArtifactStagingDirectory)/report.junit.xml'
      testRunTitle: Draugr
      failTaskOnFailedTests: false

  - task: PublishBuildArtifacts@1
    displayName: Publish the reports
    condition: succeededOrFailed()
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)
      artifactName: draugr
```

Two `prependpath` lines because there are two directories: `install.sh` puts Draugr in
`~/.local/bin`, and Draugr puts the scanners it provisions in `~/.draugr/bin`. Neither is on a
hosted agent's `PATH`.

**Pin the version for real pipelines.** `install.sh` takes `DRAUGR_VERSION`; a moving version
means a scanner change can turn a green pipeline red on a day nobody touched the code.

## The gate is the exit code

`draugr scan` exits non-zero on a `FAIL` verdict, which fails the step and the build. That is the
gate — no separate condition to write.

`condition: succeededOrFailed()` on the publishing tasks is the important part: **the run that
failed is the one whose evidence you want.** Without it the reports are published only when there
was nothing to report.

## Findings in the Tests tab

`--report junit` writes `report.junit.xml`, and `PublishTestResults@2` renders each finding as a
failed test — control and scanner as the suite, the rule and location as the test name. It is the
one panel in Azure DevOps that already knows how to show a list of things that need fixing.

Each failure carries the finding's description and a link to the advisory, so a CVE number in the
panel is something you can follow rather than something you retype into a search engine.

`failTaskOnFailedTests: false` because the scan has already decided. Letting the publish step fail
the build too means one problem reported as two.

Azure has no native SARIF ingestion, so `results.sarif` goes to the build artifacts, where another
tool or a reviewer can pick it up. It is also what your editor reads — see
[findings in your editor](findings-in-your-editor.md).

## A sticky pull-request comment

Add the publisher to the Saga and the markdown report goes on the pull request, updated in place
on each push rather than stacking a copy per run:

```yaml
config:
  reports:
    - format: markdown
  publishers:
    - kind: azure-pr-comment
```

Everything else defaults from the pipeline environment. Off a pull request it does nothing, so
the same descriptor is fine on push builds and on a laptop.

**`config.reports` is what publishers render, and `--report` is what gets written to disk.** They
are separate on purpose — a PR comment and a build artifact are different destinations — so the
`markdown` entry above is what the comment needs, whether or not `--report` mentions it.

Two things Azure needs that the descriptor cannot do for you:

**Map the access token into the step** — `SYSTEM_ACCESSTOKEN` is the one pipeline variable not
exposed to scripts by default, which is the `env:` block on the scan step above.

**Let the build identity write.** In *Project settings → Repositories → your repository →
Security*, grant **`<Project> Build Service`** the *Contribute to pull requests* permission.
Without it the API answers 403 while the token is perfectly valid.

Draugr names both of these in its error messages, so a failure points at the fix rather than at
the token.

If a branch policy requires all comments to be resolved before merging, someone has to resolve
Draugr's thread — it is created active, like any other comment.

For a gate on **only the findings a pull request introduces**, rather than everything already in
the branch, see [gate PRs on new findings](pr-diff.md). It keeps its own separate comment, so a
pipeline running both gets one for the branch and one for the delta.

## Scanning several repositories

A Saga's `url` takes a local path as well as a remote, so the cleanest way to qualify several
Azure repositories from one pipeline is to let the agent check them out and point at the results:

```yaml
# azure-pipelines.yml
resources:
  repositories:
    - repository: payments
      type: git
      name: integration/payments

steps:
  - checkout: self
  - checkout: payments
```

```yaml
# draugr.saga.yaml
components:
  - name: payments
    repositories:
      - url: ../payments        # relative to the descriptor, not the working directory
```

Draugr shells out to `git` rather than embedding a client, so a remote `url:` works exactly as
`git clone` would on that agent — which for a private Azure repository means credentials the
agent already has. Letting `checkout:` do it is simpler, and it is the path Azure keeps
authenticated for you.

## Air-gapped and self-hosted agents

Everything in [running air-gapped](air-gapped.md) applies unchanged — `DRAUGR_OFFLINE=1`, a
pre-provisioned `~/.draugr/bin`, and feeds refreshed as their own step. A self-hosted agent with a
warm scanner cache is the fastest way to run Draugr in Azure, since the scan itself is usually
seconds.
