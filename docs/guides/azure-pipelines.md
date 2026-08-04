---
title: Use in CI with Azure Pipelines
description: Run Draugr in Azure DevOps, surface findings in the Tests tab, and post a sticky pull-request comment.
section: Guides
order: 15
---

# Use in CI (Azure Pipelines)

There is no extension to install and no service connection to create. Draugr is a single binary.

## Set it up

Copy [`azure-pipelines/draugr.yml`](https://github.com/draugr-dev/draugr/blob/main/azure-pipelines/draugr.yml)
into your repository as `.azure/draugr.yml`, then:

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include: [main]
pr: none          # Azure Repos ignores this — see Pull requests below

pool:
  vmImage: ubuntu-latest

steps:
  - template: .azure/draugr.yml
    parameters:
      saga: draugr.saga.yaml
```

That installs Draugr, provisions the scanners, scans, gates a pull request on what it introduced,
and publishes findings to the Tests tab.

| Parameter | Default | |
|---|---|---|
| `saga` | `draugr.saga.yaml` | the descriptor to scan |
| `mode` | `auto` | `auto` (scan on push, diff on a pull request), `scan`, or `diff` |
| `version` | latest | pin a release — **do this for real pipelines** |
| `tools` | `true` | provision the scanners the controls need |
| `failOnNewPriority` | `P1` | fail a pull request on a new finding at or above this priority |
| `publishResults` | `true` | Tests tab and build artifacts |

**Copy it rather than referencing it remotely.** Azure can pull a template from a GitHub
repository resource, but that needs a service connection and means your pipeline changes when we
change the template. A copied file is one `curl` to update and pinned by your own git history.

### Two one-time settings

Neither can come from a descriptor or a template, and both are needed before Draugr can comment on
a pull request. Skip them and everything else still works.

1. **Build validation policy** — without one there are no pull-request builds at all.
   *Project settings → Repositories → your repo → Policies → your branch → Build Validation → `+`*.
   Start it **optional**, not required.
2. **`Contribute to pull requests`** for **`<Project> Build Service`** —
   *Project settings → Repositories → your repo → Security*. Without it the comment gets a 403
   while the token is perfectly valid.

Draugr names both in its error messages, so a failure points at the fix.

## Pull requests

**Azure Repos ignores `pr:` in YAML.** Silently — no build, no warning. Pull-request builds come
from the build validation policy above. (`pr:` works only when the pipeline's source is GitHub or
Bitbucket, which is why the key exists.)

### A sticky comment

Add the publisher to the Saga and the Markdown report goes on the pull request, updated in place
on each push rather than stacking a copy per run:

```yaml
config:
  reports:
    - format: markdown
  publishers:
    - kind: azure-pr-comment
```

Everything else defaults from the pipeline environment, and off a pull request it does nothing —
so the same descriptor works on push builds and on a laptop. `SYSTEM_ACCESSTOKEN` must be mapped
into the step (the template does this); Azure does not expose it to scripts by default.

`config.reports` is what publishers render; `--report` is what gets written to disk. Different
destinations, so the `markdown` entry above is what the comment needs regardless of `--report`.

If a branch policy requires all comments resolved before merging, someone has to resolve Draugr's
thread — it is created active, like any other.

### Gating on new findings

`mode: auto` does this for you. Written out, it is two scans and a comparison:

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

Three details that are easy to get wrong:

- **`--no-gate` on both scans.** A scan exits non-zero on `FAIL`, which under `set -e` kills the
  step before the diff runs — and the base scan fails on any repository with a backlog. `--no-gate`
  suppresses the verdict's exit code only; a scan that could not *run* still fails. `|| true`
  cannot tell those apart.
- **`$BUILD_SOURCEVERSION` to get back.** A pull-request build checks out `refs/pull/N/merge`,
  which is on no branch, so `git checkout -` cannot find its way home.
- **Priority, not severity.** `--fail-on-new-priority` folds in the component's exposure and
  criticality, so it blocks a critical finding in something exposed and lets one in a sandbox
  through.

The diff keeps its own comment, so a pipeline running both leaves one for the branch and one for
the delta. See [gate PRs on new findings](pr-diff.md) for how findings are matched across scans.

## Findings in the Tests tab

`--report junit` writes `report.junit.xml`, and `PublishTestResults@2` renders each finding as a
failed test — control and scanner as the suite, rule and location as the name. Each failure
carries the description and a link to the advisory, so a CVE number is something you can follow.

Two conditions matter:

- `condition: succeededOrFailed()` on the publishing tasks — **the run that failed is the one
  whose evidence you want.**
- `failTaskOnFailedTests: false` — the scan has already decided; failing here too reports one
  problem as two.

Azure has no native SARIF ingestion, so `results.sarif` goes to the build artifacts, where another
tool or your editor can read it ([findings in your editor](findings-in-your-editor.md)).

The gate itself needs no wiring: `draugr scan` exits non-zero on `FAIL`, which fails the build.

## What the template does

The [template](https://github.com/draugr-dev/draugr/blob/main/azure-pipelines/draugr.yml) is
readable and commented; the two things worth knowing are that `install.sh` puts Draugr in
`~/.local/bin` and Draugr puts provisioned scanners in `~/.draugr/bin`, so **both** need
`prependpath` on a hosted agent — and that `fetchDepth: 0` is required, since a diff needs the
base branch's commit.

## Several repositories

A Saga's `url` takes a local path, so let the agent check them out:

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

A remote `url:` also works — Draugr shells out to `git`, so it behaves exactly as `git clone`
would on that agent. Letting `checkout:` do it is simpler and keeps Azure's credentials in play.

## Air-gapped and self-hosted agents

[Running air-gapped](air-gapped.md) applies unchanged: `DRAUGR_OFFLINE=1`, a pre-provisioned
`~/.draugr/bin`, and feeds refreshed as their own step. A self-hosted agent with a warm scanner
cache is the fastest way to run Draugr in Azure — the scan itself is usually seconds.
