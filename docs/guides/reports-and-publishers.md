---
title: Reports & publishers
description: Render multiple report formats and deliver them with declarative publishers.
section: Guides
order: 40
---

# Reports & publishers

Draugr separates the **report** (the "what" — a rendered format) from the **publisher** (the
"where" — a destination). Configure both in the Saga's `config.reports` / `config.publishers`,
and every rendered report is delivered to every publisher — even on a FAIL verdict, so you
always get evidence.

## Report formats

Scan results render through a pluggable **Reporter**, selected on the CLI with
`draugr scan --format` or declared per format under `config.reports`:

| Format | Purpose |
|--------|---------|
| `console` | human summary on stdout (default) — verdict, P1–P4 counts, "fix first" |
| `markdown` | portable report for MR comments, wikis, Slack |
| `html` | self-contained HTML report — searchable, filterable, and carrying its own SARIF and TSV downloads. See [below](#the-html-report) |
| `junit` | JUnit XML — surfaces findings in CI test panels (GitLab, Jenkins, Azure DevOps…) |
| `json` | machine-readable report |
| `sarif` | SARIF 2.1.0 for code-scanning dashboards |
| `vex` | [OpenVEX](vex.md) — which of these vulnerabilities actually affect your product, for the people who consume your SBOM |
| `gitlab-sast` | GitLab's own security schema, for its Vulnerability Report. Written as a build artifact, not uploaded — GitLab has no endpoint. See [below](#gitlabs-own-report-formats) |
| `gitlab-dependency-scanning` | the same, for vulnerable dependencies — each with the package and version GitLab requires |
| `gitlab-secret-detection` | the same, for leaked credentials |
| `gitlab-container-scanning` | the same, for vulnerable packages in a container image — each with the image and the operating system GitLab requires |
| `gitlab-codequality` | GitLab Code Quality — every finding, in the merge request, on **any** tier |
| `template` | custom payload from a Go `text/template` (inline or file) — no code needed |

`-o/--output <dir>` always writes `report.json` + `results.sarif` regardless of `--format`.

### Telling a partial run from a clean one

A gate reading `report.json` should check more than `verdict`. A run where a scanner never started
and a run that found nothing both produce findings-shaped output, and the difference is what your
pipeline should do about it — one is broken infrastructure, the other is work.

| Field | Meaning |
|---|---|
| `controls[].scanErrors` | what stopped that control, in the scanner's own words. Its counts then describe what the scanners that *did* run found, which is not the same as what is there. A control that produced nothing at all is still listed, with `"verdict": "fail"` and no counts. |
| `notMeasured[]` | a scanner that was planned and then not run because it could not answer the question its target asked — the control, scanner, component and reason. Not an error: nothing went wrong, and no `scanErrors` are recorded for it. |

Both are omitted when there is nothing to report, so a clean run's document is unchanged.

```bash
draugr scan draugr.saga.yaml -o out/
jq -e '[.controls[].scanErrors // empty] | length == 0' out/report.json   # fail the build on a partial run
```

## Declare formats and destinations

```yaml
config:
  reports:
    - format: sarif        # for code scanning / dashboards
    - format: markdown     # a portable report (MR comment, wiki)
    - format: html         # a shareable, browser-viewable artifact
    - format: template     # custom payload from a Go text/template
      template: "{{.Verdict}}: P1={{.Priorities.P1}} P2={{.Priorities.P2}}\n"
      filename: summary.txt   # optional; overrides the default output filename
  publishers:
    - kind: file           # write each report to a directory
      dir: ./out           # → ./out/results.sarif, ./out/report.md, ./out/report.html, ./out/summary.txt
```

The **`template`** format renders a
[Go `text/template`](https://pkg.go.dev/text/template) against a stable view of the scan —
`.Release`, `.Verdict`, `.Pass`, `.Priorities.{P1..P4}`, `.Controls`, and `.Findings` (each
with `.Priority .Level .Score .Control .Tool .RuleID .Message .Location`). Use it for a
bespoke summary line, a Slack payload, or any custom text without writing code.

## Built-in publishers

| Kind | Delivers to | Config |
|------|-------------|--------|
| `file` | a local directory (one file per report format) | `dir` |
| `github` | GitHub code scanning (uploads the `sarif` report to the Security tab) | `repo`, `commit`, `ref` (default from the GitHub Actions env); token from `$GITHUB_TOKEN` (or `tokenEnv`) |
| `github-pr-comment` | a sticky pull-request comment (posts the `markdown` report) | `repo`, `pr` (default from the env); token from `$GITHUB_TOKEN` (or `tokenEnv`) |
| `azure-pr-comment` | a sticky Azure DevOps pull-request comment (posts the `markdown` report) | `org`, `project`, `repo`, `pr` (default from the Azure Pipelines env); token from `$SYSTEM_ACCESSTOKEN` (or `tokenEnv`) |
| `gitlab-mr-comment` | a sticky GitLab merge-request comment (posts the `markdown` report) | `repo`, `pr` (default from the GitLab CI env); token from `$GITLAB_TOKEN` (or `tokenEnv`) |

No publisher stores a secret in the Saga — every token comes from an environment variable, and
each no-ops outside its own context (not in CI, or no PR) so the same Saga still runs locally.
Every comment publisher upserts one **sticky** comment, updated in place on each push, and
pairs with
[`draugr diff --publish`](pr-diff.md) for a PR security delta. The `github` publisher pairs with
[code scanning](code-scanning.md).

### Azure DevOps

In a pipeline everything defaults from the environment, so the whole configuration is:

```yaml
config:
  reports:
    - format: markdown
  publishers:
    - kind: azure-pr-comment
```

Two things Azure requires that nothing in the Saga can do for you:

**Map the access token into the step.** `SYSTEM_ACCESSTOKEN` is the one pipeline variable not
exposed to scripts by default:

```yaml
- script: draugr scan draugr.saga.yaml
  env:
    SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

**Let the build identity write.** In *Project settings → Repositories → your repo → Security*,
grant **`<Project> Build Service`** the *Contribute to pull requests* permission. Without it the
API answers 403 with the token perfectly valid, so Draugr names the permission in the error
rather than leaving you re-checking the token.

And a pull-request build has to exist in the first place: Azure Repos ignores a `pr:` trigger, so
that comes from a build validation branch policy. See
[Azure Pipelines](azure-pipelines.md#two-one-time-settings).

Azure models a PR comment as a *thread*, so the sticky comment is the first comment of the thread
carrying Draugr's marker. The marker is matched on that first comment only — a reviewer who
quotes the report in a reply gets their words left alone.

The thread is created **active**. If your branch policy requires all comments to be resolved
before merging, someone has to resolve Draugr's thread; set a distinct `marker` per pipeline if
you run more than one Draugr scan against the same pull request.

### GitLab

Everything defaults from the runner environment, so the whole configuration is:

```yaml
config:
  reports:
    - format: markdown
  publishers:
    - kind: gitlab-mr-comment
```

**`CI_JOB_TOKEN` cannot post the comment.** GitLab puts it in every job, and it is read-only on the
notes API — it can list notes and not write one. So the publisher reads `GITLAB_TOKEN`, which has to
be a project or group access token with **`api`** scope and at least **Developer** role, added under
*Settings → CI/CD → Variables* as a masked variable:

```yaml
draugr:
  variables:
    GITLAB_TOKEN: $DRAUGR_GITLAB_TOKEN
```

Draugr names this in the error rather than letting the job token produce an unexplained 401.

A merge-request pipeline has to exist for there to be anything to comment on. Branch pipelines
carry no `CI_MERGE_REQUEST_IID`, and the publisher no-ops there, so one Saga serves both.

For the pipeline itself, see [use in CI with GitLab](gitlab-ci.md).

The project is taken from `CI_PROJECT_ID`. Setting `repo` to a full path instead works too, groups
and all — `group/subgroup/project` is encoded for you.

Draugr's own notes are told apart from GitLab's by the marker, and system notes ("added 3 commits",
"marked as draft") are never candidates for the edit. The note list is read in full rather than a
first page, so a long discussion cannot push the marker out of sight and turn the sticky comment
into a new one each run.

## GitLab's own report formats

GitLab does not read SARIF. It reads its own schema, and there is no endpoint to upload one to — a
job declares `artifacts: reports:` and the runner collects the file. So GitLab's equivalent of
pushing to code scanning is a **report format**, not a publisher, and it composes with `-o` and the
`file` publisher you already have.

```yaml
config:
  reports:
    - format: gitlab-sast
    - format: gitlab-secret-detection
    - format: gitlab-codequality
  publishers:
    - kind: file
      dir: ./draugr-out
```

```yaml
# .gitlab-ci.yml
artifacts:
  reports:
    sast: draugr-out/gl-sast-report.json
    secret_detection: draugr-out/gl-secret-detection-report.json
    codequality: draugr-out/gl-code-quality-report.json
```

### Which one a reader actually sees depends on the tier

| Surface | Fed by | Tier |
|---|---|---|
| Merge request **Reports** tab | `gitlab-codequality` | Free, Premium, Ultimate |
| Diff annotations, inline | `gitlab-codequality` | Ultimate |
| Vulnerability Report, MR security widget | `gitlab-sast`, `gitlab-dependency-scanning`, `gitlab-secret-detection`, `gitlab-container-scanning` | Ultimate |

On a Free or Premium project the security reports are produced and stored and nothing displays
them. That is why `gitlab-codequality` carries **every** finding whatever its control, and the
typed security reports carry only their own: the untyped one is what makes sure nothing Draugr
found is invisible, whatever plan you are on.

### Severity means something different in each, on purpose

The security reports carry the **flaw's** severity. GitLab's merge-request approval policies gate
on that field, and a Draugr priority has already folded in the component's exposure and
criticality — handing one over would have those policies apply that context a second time.

Code Quality carries the **priority**, because it has no policy engine behind it. It is a list a
reviewer reads in order, and the useful order is the one that accounts for what the component is
exposed to. The flaw's severity leads the description, so nothing is lost.

| Priority | Code Quality severity |
|---|---|
| P1 | `blocker` |
| P2 | `critical` |
| P3 | `major` |
| P4 | `minor` |

### What these reports leave out

**Suppressed findings.** GitLab has no notion of one somebody already accepted: it would show it as
open and wait to be dismissed, asking again for a decision your Saga records with its reason and its
author. They stay in Draugr's own report, marked.

**`container_scanning`.** GitLab requires an image and an operating system on every container
finding, which Draugr's image findings do not yet carry as fields — and filling a required field
with a guess is worse than a report that does not exist. Those reach the merge request through
`gitlab-codequality` in the meantime.

`dependency_scanning` was in the same position and no longer is: a dependency finding carries its
package, version and purl as fields, so the schema's requirement is met with facts.

## Compact output, for tools and agents

`--compact` strips what only a human reads — indentation, and the rule descriptions and
remediation text Draugr relays from each scanner — while keeping the output **valid SARIF**:

```bash
draugr scan draugr.saga.yaml --format sarif --compact
```

Measured on Draugr's own repository: **17,355 → 5,831 bytes**, the same 8 findings, still
parseable by any SARIF consumer.

Rule documentation is the bulk of a report — around 60% of it — and a consumer that can follow
a link doesn't need it inlined. So `helpUri` survives compaction and the paragraphs don't:
**the pointer stays, the prose goes.** The scanner tag on each rule stays too, since that's how
a consumer knows which tool found what.

Use it when something *acts* on the report — a script, a policy engine, an AI agent paying for
every byte of context. **Don't use it for your editor**: the descriptions it removes are exactly
what a SARIF viewer shows you beside a finding. And don't use it for GitHub code scanning, which
renders those same fields on an alert.

`--compact` has no effect on `console`, `markdown`, `html` or `junit` — making the human formats
harder to read would be the opposite of the point.

The `sarif` report is also what your editor reads — see
[see findings in your editor](findings-in-your-editor.md) for inline diagnostics in VS Code
and JetBrains.

For the exact schema of `config.reports` / `config.publishers`, see the
[Saga schema](../reference/saga-schema.md#configreports-and-configpublishers); for the full
catalog of reporters and publishers, see the
[integrations catalog](../reference/catalog.md#reporters).

## The HTML report

One file, no external assets — safe to email, attach to a build, or open from disk.

**It carries its own data.** The report embeds the full SARIF and a tab-separated export of every
finding, offered as ordinary download links:

- `results.sarif` — the complete report, for another tool or a code-scanning upload.
- `findings.tsv` — one row per finding, ready for a spreadsheet. Tab-separated rather than
  comma-separated because finding messages contain commas constantly: CSV would need quoting that
  spreadsheet importers handle inconsistently, and several locales expect `;` as the delimiter.
  Nothing in a finding contains a tab, so TSV needs no escaping and opens on a double-click.

The TSV covers **every** finding including suppressed ones, each marked with the reason it was
set aside — the download is the record, and you can filter in the spreadsheet.

**Search and filtering** are progressive enhancement. The page renders complete without
JavaScript: the full table, both downloads, and every section. The script only reveals a search
box and per-priority, per-severity and per-control toggles, so a reader whose viewer strips
scripts sees the whole report rather than controls that do nothing.

**Suppressed findings get their own section**, each with its justification, because "who decided
this was acceptable, and when" is the question the report exists to answer.

The footer records when the scan ran, which version produced it, and the run's statistics.

A very large scan can produce more SARIF than is sensible to inline; past 8 MiB the report says
so and points at `-o` instead.
