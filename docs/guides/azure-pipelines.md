---
title: Use in CI with Azure Pipelines
description: Run Draugr in Azure DevOps, surface findings in the Tests tab, and post a sticky pull-request comment.
section: Guides
order: 15
---

# Use in CI (Azure Pipelines)

Draugr is a single binary with no Azure-specific parts, so there is no extension to install and
no service connection to create.

## The short version

Copy [`azure-pipelines/draugr.yml`](https://github.com/draugr-dev/draugr/blob/main/azure-pipelines/draugr.yml)
into your repository — say as `.azure/draugr.yml` — and your pipeline is this:

```yaml
trigger:
  branches:
    include: [main]
pr: none          # Azure Repos ignores this; see Pull-request builds below

pool:
  vmImage: ubuntu-latest

steps:
  - template: .azure/draugr.yml
    parameters:
      saga: draugr.saga.yaml
```

That installs Draugr, provisions the scanners, scans, gates a pull request on what it introduced,
and publishes the findings to the Tests tab. Its parameters:

| Parameter | Default | |
|---|---|---|
| `saga` | `draugr.saga.yaml` | the descriptor to scan |
| `mode` | `auto` | `auto` (scan on push, and diff on a pull request), `scan`, or `diff` |
| `version` | latest | pin a release — **do this for real pipelines** |
| `tools` | `true` | provision the scanners the controls need |
| `failOnNewPriority` | `P1` | fail a pull request on a new finding at or above this priority |
| `publishResults` | `true` | Tests tab and build artifacts |

### Two things to set up once

Neither can be done from a descriptor or a template, and both are needed before Draugr can comment
on a pull request:

1. **A build validation policy**, or there are no pull-request builds at all — Azure Repos ignores
   a `pr:` trigger. *Project settings → Repositories → your repository → Policies → your branch →
   Build Validation → `+`*. Start it **optional** rather than required.
2. **`Contribute to pull requests` for the build identity**, or the comment gets a 403 while the
   token is perfectly valid. *Project settings → Repositories → your repository → Security*, grant
   it to **`<Project> Build Service`**.

Draugr names both in its error messages, so a failure points at the fix rather than at your token
— but they are easier to do now than to diagnose later. Skip them and everything except the
pull-request comment still works.

**Copying it in beats referencing it remotely.** Azure can pull a template from a GitHub repository
resource, but that needs a service connection, and it means your pipeline changes when we change
the template. A vendored file is one `curl` to update and is pinned by your own git history.

The rest of this page is what that template does, written out. Worth reading once — a template
you cannot debug is worse than the twenty lines it saved you.

## The long version

```yaml
# azure-pipelines.yml — equivalent to the template above
trigger:
  branches:
    include: [main]

# Azure Repos ignores a `pr:` trigger — see "Pull-request builds" below. Declaring it none
# makes that explicit rather than leaving a block that looks like it does something.
pr: none

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
    fetchDepth: 0                 # a diff against the base branch needs its commit

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

## Pull-request builds

**Azure Repos does not honour a `pr:` trigger in YAML.** It is silently ignored — no build, no
warning, and a `pr:` block in the file that reads as though pull requests are covered. (It *does*
work for a pipeline whose source is GitHub or Bitbucket, which is why the key exists at all.)

For an Azure Repos repository, pull-request builds come from a **branch policy** on the target
branch:

*Project settings → Repositories → your repository → Policies → your branch → Build Validation →
`+`* — select this pipeline, and choose whether it is **required** (blocks completion) or
**optional** (runs and reports, does not block).

Optional is the honest place to start: it produces the same build and the same PR comment without
turning a first trial of a security gate into something that blocks everyone's merges on day one.

Everything below about the pull-request comment depends on this — without a build validation
policy there is no pull-request build, so there is nothing to comment from.

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

## Gate on new findings

The scan above gates on everything in the branch, which is the right gate for `main` and the
wrong one for a first pull request against a codebase with a backlog. To gate on **what this
change introduced**, scan both sides and compare:

```yaml
  - script: |
      set -euo pipefail
      target="${SYSTEM_PULLREQUEST_TARGETBRANCH#refs/heads/}"

      git checkout -q --detach "origin/$target"
      draugr scan draugr.saga.yaml --no-gate --report sarif -o "$(Pipeline.Workspace)/base"

      git checkout -q --detach "$BUILD_SOURCEVERSION"
      draugr scan draugr.saga.yaml --no-gate --report sarif -o "$(Pipeline.Workspace)/head"

      draugr diff "$(Pipeline.Workspace)/base/results.sarif" \
                  "$(Pipeline.Workspace)/head/results.sarif" \
                  --publish --fail-on-new-priority P1
    displayName: Gate on new findings
    condition: eq(variables['Build.Reason'], 'PullRequest')
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

There is no `mode: auto` here as there is in the GitHub Action — Azure has no first-party task, so
the two scans are written out. Four things in that snippet are the whole trick:

**`--no-gate` on both scans.** A scan exits non-zero on a `FAIL` verdict, which under `set -e`
kills the step before the diff ever runs — and on a repository with any backlog, the base scan
fails every time. `--no-gate` suppresses the *verdict's* exit code and nothing else: a scan that
could not run still fails the step. `|| true` cannot make that distinction, and swallows the
failure that leaves no report for the diff to read.

**`$BUILD_SOURCEVERSION` to get back.** A pull-request build checks out `refs/pull/N/merge`, a
merge commit that is not on any branch, so `git checkout -` will not find its way home.

**`condition:` on the build reason**, so the step is skipped entirely on push builds, where there
is no pull request and nothing to compare against.

**`--fail-on-new-priority P1`** rather than a severity: priority folds in the component's declared
exposure and criticality, so it blocks on a critical finding in something exposed and lets one in
a sandbox through. Use `--fail-on-new` if you want the raw ladder.

The diff gets **its own comment**, separate from the report the publisher posts, so a pipeline
running both leaves one comment for the branch and one for the delta.

See [gate PRs on new findings](pr-diff.md) for how findings are matched across the two scans, and
why line numbers and re-scoring do not make an old finding look new.

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
