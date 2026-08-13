---
title: Use in CI with GitLab
description: Run Draugr in GitLab CI, post a sticky merge-request comment, and feed GitLab's own security and Code Quality reports.
section: Guides
order: 16
---

# Use in CI (GitLab)

There is no extension to install and no CI/CD Catalog component to add. Draugr is a single binary.

## Set it up

Include the template and add one variable.

```yaml
# .gitlab-ci.yml
include:
  - project: draugr-dev/draugr
    ref: v0.86.0                    # pin a release; `main` moves
    file: /gitlab-ci/draugr.yml

stages: [test]
```

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

Without the variable the job still finishes and still gates — only the comment is missing, and the
run says so.

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

On Free and Premium the security reports are produced and stored and nothing displays them. That
is why `gitlab-codequality` carries **every** finding whatever its control, and the typed security
reports carry only their own — the untyped one is what keeps findings visible on any plan.

See [reports & publishers](reports-and-publishers.md#gitlabs-own-report-formats) for the severity
mapping in each, and what they deliberately leave out.

## Tune it

Override any variable on the job:

```yaml
draugr:
  variables:
    DRAUGR_SAGA: services/api/draugr.saga.yaml
    DRAUGR_VERSION: v0.86.0            # empty installs the latest release
    DRAUGR_FAIL_ON_NEW_PRIORITY: P2    # empty disables the differential gate
    DRAUGR_TOOLS: "false"              # a runner image that already has the scanners
```

## Scanners the runner needs

`draugr tools install` provisions the scanners Draugr distributes and can verify. **Semgrep is not
one of them** — it installs through pipx — so a descriptor enabling `sast` needs Semgrep in the
runner image. The template runs `draugr doctor`, which names what is missing and where it comes
from, rather than letting a control report that it quietly found nothing.

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
