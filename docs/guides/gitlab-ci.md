---
title: Use in CI with GitLab
description: Run Draugr in GitLab CI, post a sticky merge-request comment, and feed GitLab's own security and Code Quality reports.
section: Guides
order: 16
---

# Use in CI (GitLab)

There is no extension to install and no CI/CD Catalog component to add. Draugr is a single binary.

A complete, commented `.gitlab-ci.yml` is at
[`examples/gitlab-ci.yml`](../../examples/gitlab-ci.yml) — copy that if you would rather start from
a working file than from prose.

## Set it up

Include the template and add one variable.

```yaml
# .gitlab-ci.yml
include:
  - remote: 'https://raw.githubusercontent.com/draugr-dev/draugr/v0.89.0/gitlab-ci/draugr.yml'

stages: [test]
```

**`remote:`, not `project:`.** `include: project:` resolves against your own GitLab instance, and
Draugr is not on it — that form fails with a project-not-found error that reads like a permissions
problem. Pin the tag rather than `main`: the URL is fetched at pipeline time, so an unpinned
include changes under a pipeline that has not changed.

If your runners have no route to raw.githubusercontent.com, copy `gitlab-ci/draugr.yml` into your
own repository and `include: local:` it; nothing in it is specific to where it is hosted.

Then, in *Settings → CI/CD → Variables*, add a **masked** variable named `GITLAB_TOKEN` holding a
project or group access token with **`api`** scope and at least **Developer** role.

That variable is the one thing GitLab cannot do for you, and it is worth knowing why.

## `CI_JOB_TOKEN` will not work, and it is the obvious thing to reach for

GitLab puts `CI_JOB_TOKEN` in every job, so it is the credential already to hand. It is **read-only
on the notes API**: it can list a merge request's comments and cannot write one. A pipeline
configured to use it gets a 401 with nothing in it to suggest the token is the wrong *kind* rather
than the wrong value.

Draugr names that in the error rather than leaving you to find it:

```
draugr: gitlab-mr-comment publisher missing: $GITLAB_TOKEN (a project or group access token with
`api` scope, set as a masked CI/CD variable; CI_JOB_TOKEN is read-only on the notes API and cannot
post)
```

Without the variable the job fails, because `--publish` was asked for and could not be honoured —
but it fails **with the verdict**, not instead of it:

```
draugr: differential gate: 1 new finding(s) at or above the threshold
  (publishing also failed: gitlab-mr-comment publisher missing: $GITLAB_TOKEN …)
```

The gate is what the job is for. A run that reported only the token would send you to fix a
credential while the P1 the change introduced went unmentioned.

## What the job does

**On a merge request** it scans the head, scans the merge base, and reports the delta as a sticky
comment — one note per merge request, edited in place on each push rather than stacking up. The
gate is on what the change *introduces* (`DRAUGR_FAIL_ON_NEW_PRIORITY`, default `P1`), not on the
backlog it inherited.

**On the default branch** it scans the whole descriptor and applies the descriptor's own gate.

Both publish GitLab's own reports as artifacts.

### The merge base is usually not in the checkout

GitLab clones **20 commits deep** by default, so `CI_MERGE_REQUEST_DIFF_BASE_SHA` — the commit a
merge request should be compared against — is frequently absent. The template fetches that one
commit explicitly, which is far cheaper than a full history:

```yaml
git fetch --no-tags --depth 1 origin "${CI_MERGE_REQUEST_DIFF_BASE_SHA}"
```

If your instance refuses to serve a bare SHA, set `GIT_DEPTH: 0` on the job instead. The symptom is
a `git worktree add` that fails on a real merge request and never on a small test repository.

## Where the findings show up, and on which plan

GitLab does not read SARIF. It reads its own schema, collected from `artifacts: reports:` — so
Draugr renders GitLab's formats rather than uploading anything.

| Surface | Fed by | Tier |
|---|---|---|
| Merge request **Reports** tab | `gitlab-codequality` | Free, Premium, Ultimate |
| Diff annotations, inline | `gitlab-codequality` | Ultimate |
| **Vulnerability Report**, MR security widget | `gitlab-sast`, `gitlab-secret-detection` | Ultimate |
| Sticky merge-request comment | the `markdown` report | any |
| **Dependency List**, **License Compliance** | a CycloneDX SBOM, from `config.sbom` | Ultimate |

On Free and Premium the security reports are produced and stored and nothing displays them. That
is why `gitlab-codequality` carries **every** finding whatever its control, and the typed security
reports carry only their own — the untyped one is what keeps findings visible on any plan.

See [reports & publishers](reports-and-publishers.md#gitlabs-own-report-formats) for the severity
mapping in each, and what they deliberately leave out.

### The Dependency List and License Compliance both come from the SBOM

GitLab reads both out of a **CycloneDX SBOM** rather than a report of its own — the older
`license_scanning` artifact is not what populates either. Two things it is strict about, and Draugr
handles both:

- **Spec version.** GitLab reads CycloneDX **1.4, 1.5 or 1.6** and rejects anything else outright.
  Syft emits 1.7, so a raw Syft SBOM is reported as *"could not be parsed"* rather than partially
  read.
- **Its own property namespace, behind a required flag.** The manifest a package came from is
  stated as `gitlab:dependency_scanning:input_file:path`, and GitLab reads it only if the document
  also declares `gitlab:meta:schema_version`. Without that flag every `gitlab:` property is ignored
  — quietly, because packages still show names, versions and licences from plain CycloneDX and
  GitLab infers the packager from a purl. What goes missing is *Location*, and with it GitLab's own
  dependency scanning against the SBOM.

So Draugr renders a **`gitlab-cyclonedx`** view of the SBOM it already produces: the same packages,
at a version GitLab accepts, with those two facts translated from what Syft recorded. Draugr's own
SBOM is written beside it and left exactly as it is, so nothing else that consumes it is affected.

Turn the SBOM on in the descriptor and the template does the rest:

```yaml
config:
  sbom:
    enabled: true
    format: cyclonedx-json
    scope: both
```

The template renders `gitlab-cyclonedx` and collects `draugr-out/gl-sbom-*.cdx.json`, and that one
artifact fills both *Secure → Dependency List* and the merge request's *License Compliance* tab —
each package with its version, licence, packager and the file it was declared in.

Without `config.sbom` there is nothing to render: the format says so rather than writing an empty
document, because an SBOM report with no SBOM behind it is a clean-looking answer to a question
nobody asked. Requires Syft, which `draugr tools install` provisions.

## Tune it

Override any variable on the job:

```yaml
draugr:
  variables:
    DRAUGR_SAGA: services/api/draugr.saga.yaml
    DRAUGR_VERSION: v0.89.0               # empty installs the latest release
    DRAUGR_FAIL_ON_NEW_PRIORITY: P2       # empty disables the differential gate
    DRAUGR_GATE_DEFAULT_BRANCH: "false"   # keep the default branch green so the widgets populate
    DRAUGR_TOOLS: "false"                 # a runner image that already has the scanners
```

## Scanners the runner needs

`draugr tools install` provisions every scanner the descriptor's controls need, Semgrep included.
Semgrep publishes no release binary, so Draugr installs it from PyPI into an environment it owns —
which needs a **Python 3.10 or newer** interpreter on the runner.

That is why the job runs on `python:3.13-slim` rather than something smaller, along with the other
half: the scanners Draugr provisions are built against glibc. An Alpine runner will install Draugr
fine and then report controls that could not run.

The template also runs `draugr doctor`, which names anything still missing and where it comes from,
rather than letting a control report that it quietly found nothing.

## Without the template

Nothing above is magic. The whole integration is the binary plus the environment GitLab already
sets:

```yaml
draugr:
  image: alpine:3.22
  script:
    - apk add --no-cache bash curl git ca-certificates
    - curl -fsSL https://draugr.dev/install.sh | sh
    - export PATH="$HOME/.local/bin:$HOME/.draugr/bin:$PATH"
    - draugr scan draugr.saga.yaml -o draugr-out --report gitlab-codequality
  artifacts:
    when: always
    reports:
      codequality: draugr-out/gl-code-quality-report.json
```

`CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID` and `CI_API_V4_URL` are read from the runner's environment,
so a Saga declaring `kind: gitlab-mr-comment` needs nothing else — and no-ops on a branch pipeline,
so one descriptor serves both.
