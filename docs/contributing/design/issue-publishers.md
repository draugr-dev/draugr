# Issue publishers

Design record for https://github.com/draugr-dev/draugr/issues/955: the `github-issue`,
`gitlab-issue` and `azure-work-item` publishers, which keep one tracking item open on the forge
while the gate fails and close it when the gate passes.

- **Status:** proposed, 2026-09-28. Decisions marked *proposed* need agreement before the build starts.
- **Intent:** the issue body. This record is the spec. It states what must be true when the work is
  done, written so each acceptance test can be lifted out of it.
- **Verified against:** `draugr` at `325a33af`, and the GitHub, GitLab and Azure DevOps
  documentation as read on 2026-09-28. Each forge fact below cites the page it came from.

<!-- toc -->
**Contents**

- [Core](#core)
  - [Interface](#interface)
  - [Gate](#gate)
  - [Branches](#branches)
  - [Scope](#scope)
  - [Retries](#retries)
- [Item](#item)
  - [Identity](#identity)
  - [Lifecycle](#lifecycle)
  - [Body](#body)
  - [Escaping](#escaping)
  - [Size](#size)
  - [Visibility](#visibility)
  - [Metadata](#metadata)
- [Configuration](#configuration)
- [Failure](#failure)
- [GitHub](#github)
- [GitLab](#gitlab)
- [Azure DevOps](#azure-devops)
- [Decisions](#decisions)
  - [Live test](#live-test)
- [Sequence](#sequence)
- [Acceptance](#acceptance)
- [Corrections](#corrections)

<!-- /toc -->

## Core

### Interface

`Publisher.Publish(ctx, []report.Artifact)` hands a publisher rendered bytes and nothing else
(`pkg/publish/publish.go`). `publish.Run` holds the full `report.Data` and does not pass it on, so
no publisher today can learn the verdict, whether the gate was disabled, the scope, the project or
the commit. Parsing the JSON artifact is not a substitute, because `publish.Run` clears `MinPriority`,
so the JSON a publisher receives has no `findings`, and it carries no Draugr version.

An optional interface closes the gap without touching the existing publishers:

```go
// RunPublisher is a Publisher whose delivery depends on the run, not only on its rendered output.
type RunPublisher interface {
	Publisher
	PublishRun(ctx context.Context, data report.Data, artifacts []report.Artifact) error
}
```

`publish.Run` calls `PublishRun` when the built publisher implements it and `Publish` otherwise.
`report.Data` gains two fields the lifecycle needs, the requested scope (below) and the
incomplete flag.

The MCP delivery path (`internal/mcp/deliver.go`) builds a `report.Data` with no CI context, and an
issue publisher there skips with the reason `no CI run`. Opening a tracking item from an
assistant's session is out of scope.

### Gate

The item follows the gate as the exit code reports it, not the raw verdict.

| Run | Item action |
|---|---|
| verdict fail, gate enabled | failing |
| scan incomplete (a scanner missing or erroring) | failing; the body lists the errors |
| verdict pass | passing |
| `--no-gate` (`Gate.Disabled`) | none; logged as `gate disabled, item left as it is` |
| `--no-publish` | none; no publisher runs |
| canceled or killed before publishing | none; nothing runs |

A publisher runs only when the scan reached a verdict, so a canceled job leaves the item as it
is. Closing on anything short of a pass would close an item the branch still fails.

### Branches

**Default branch only, unless `branches:` says otherwise.** A pull-request pipeline that passes
would close an item the default branch still fails. The token cannot be the guard, because a fork
pull request can get a write token under `pull_request_target` or with *Send write tokens to workflows
from pull requests* enabled
([GitHub](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token)).

`pkg/ci` has no notion of a default branch today. `ci.Context` gains `Branch`, `DefaultBranch`
and `PullRequest`, filled per forge:

| Forge | Branch | Default branch | Never acts |
|---|---|---|---|
| GitHub | `GITHUB_REF_NAME` on a `refs/heads/` ref | `repository.default_branch` in the event at `GITHUB_EVENT_PATH` | `pull_request`, `pull_request_target` events |
| GitLab | `CI_COMMIT_BRANCH` | `CI_DEFAULT_BRANCH` | `CI_COMMIT_BRANCH` unset (merge request and tag pipelines) |
| Azure DevOps | `BUILD_SOURCEBRANCH` | `defaultBranch` from `GET _apis/git/repositories/{BUILD_REPOSITORY_ID}` | `BUILD_REASON=PullRequest` |

Azure exposes no default-branch variable, so its lookup is an API call made by the publisher, and
it needs read access to code (`vso.code` on a PAT). Setting `branches:` skips it.

A run that does not act says why, in the scan output, the way `github-pr-comment` does outside a
pull request.

### Scope

**A narrowed run acts only on its own item.** A passing `--controls sca` run must not close an
item a full run opened for a leaked secret.

The scope key is built from the selectors **as requested**, not from the components they resolve
to. `engine.Scope.Resolve` turns `--labels`, `--exposure` and `--criticality` into component names
before the report is built (`internal/cli/scan.go`), so a key derived from `report.Scope` changes
whenever a component gains or loses a label, and the next run opens a second item. For the same
reason `report.AutomationID` is not reused.

| Run | Scope key |
|---|---|
| no narrowing | `all` |
| `--controls sca,secrets` | `controls=sca,secrets` |
| `--labels team=payments --controls sca` | `controls=sca;labels=team=payments` |

Each selector is sorted and the selectors appear in a fixed order. The key goes into the marker
and, when it is not `all`, into the title.

This is deliberately stricter than the server's covered controls, where a run closes findings
within the controls it looked at and ignores components (`draugr-server`, `internal/store/finding.go`).
An item is a single object with one state, not a set of findings, so there is nothing to close
partially. The expected configuration is one scheduled full run, which has the key `all`.

### Retries

The shared client in `pkg/publish/retry.go` retries 429, 502, 503 and 504, honors `Retry-After`
up to 8 seconds, and never replays a request that got no response unless it was a GET. Issue
writes need more:

- **GitHub's secondary limit answers 403**, with `retry-after` or `x-ratelimit-remaining: 0` and
  `x-ratelimit-reset`; without either header the documented wait is at least one minute
  ([rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)).
  A 403 carrying those headers is a rate limit; any other 403 is a permission error.
- **Azure sends `Retry-After` on a 200** while it is delaying requests
  ([rate limits](https://learn.microsoft.com/en-us/azure/devops/integrate/concepts/rate-limits)),
  so the header is honored on every response, as a delay before the next request.
- **GitLab application limits are not reflected in `RateLimit-*` headers**, so a 429 can arrive
  with quota apparently left; without `Retry-After` the wait is 60 seconds
  ([GitLab.com rate limits](https://docs.gitlab.com/user/gitlab_com/rate_limits/)).
- **Writes are serial and at least one second apart** on GitHub
  ([best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)).

The per-wait cap rises to 60 seconds for issue publishers, with a total budget of three minutes
per run. A create that got no response is not replayed; the next run finds the item by its marker,
or finds two and closes the newer (below).

## Item

### Identity

An item is ours when it carries **the label and the marker**. The label narrows the list on the
server; the marker in the body tells our item from a person's that reuses the label:

```
<!-- draugr:issue v1 project=<project> scope=<scope key> -->
```

GitLab adds the token's own user as `author_username`, from `GET /user`. GitHub and Azure have no
equivalent a CI token can answer (`GITHUB_TOKEN` is an installation token and cannot call
`GET /user`), so on those two identity is label and marker. Somebody with triage access can forge
both; the consequence is that Draugr edits or closes an item they wrote on purpose to look like
ours.

- **Looked up by listing, never by search.** GitHub search allows 30 requests a minute and does
  not document how fresh its index is ([search](https://docs.github.com/en/rest/search/search)).
- **Several matches: the oldest is kept** and the others are closed as duplicates, with a comment
  naming the one kept. Two runs racing can each create an item, and no forge offers an idempotent
  create.
- **The project name is required.** A descriptor with no `project:` fails validation when it
  configures an issue publisher, because every run of every such descriptor would share one item.

### Lifecycle

Only open items are looked up. A closed item is never read, reopened or edited again.

| Gate | Open item | Action |
|---|---|---|
| fails | none | create, with label and marker |
| fails | one | rewrite the body **only if it changed** |
| passes | one | comment that the gate passed, naming the run, then close |
| passes | none | nothing |

**Closing an item does not accept the risk.** Accepting is a `config.exclude` entry with a
`reason`, an `acceptedBy` and an `expires`, which stays in the report. An item closed by hand while
the gate still fails is left closed, and the next failing run creates a new one. The body says how
to accept, so the way out is written down.

**Writes happen on change; comments on transitions.** Azure DevOps Services allows 10,000 REST
updates per work item and GitLab 5,000 comments per issue, and a write can notify. The body
carries the run that last changed it, not the latest run, so an unchanged finding set produces an
identical body and no write. Comments are posted on close and on duplicate, never per run.

### Body

Title: `Draugr gate fails: <project>`, with ` (<scope key>)` appended when the scope is not `all`.

The body, in order:

1. The marker.
2. The verdict line: the gate that failed (threshold and band), and `incomplete` when it was.
3. Open findings by priority and accepted findings by priority, **as two counts, never summed**.
   A suppressed finding stays in the report, so the two legitimately differ.
4. The failing controls. With `details: findings`, the findings as well, in priority order, which
   is fix order: priority, severity, rule, scanner, location, and the fix where one is known.
5. Errors, when the scan was incomplete: one list item per error, naming the component, the
   control and the message.
6. The run that last changed the body: job URL, commit, descriptor digest, Draugr version.
7. How to accept, with a `config.exclude` example.
8. A line saying the item closes itself when the gate passes.

The PR-comment markdown (`pkg/report/markdown.go`) is not reused. It opens with emoji, stops at 25
findings, has no size cap, does not render the scope and emits scanner text unescaped. The body
comes from one model rendered twice, as Markdown for GitHub and GitLab and as HTML for Azure,
whose `System.Description` is HTML. The module has no Markdown library and does not need one.

The body is a surface a user reads, so **three variants are rendered and one is chosen before the
renderer is built**.

### Escaping

Every rule, message, path, component name and decision reason is scanner- or author-supplied.
None of it may act on the forge:

- **Mentions and references.** `@name` notifies, and `#123`, `!123` and `GH-123` link and
  back-link. Every such string goes in a code span, with a fence longer than any backtick run
  inside it, and newlines collapsed.
- **GitLab quick actions.** A line starting with `/` in a description or note runs as a command
  ([quick actions](https://docs.gitlab.com/user/project/quick_actions/)), and GitLab does not
  document that a code span prevents it. The invariant is therefore structural. **Every line of the
  body starts with a character Draugr wrote**, so no line can start with scanner text.
- **Azure HTML.** Every string is HTML-escaped.

### Size

Findings are truncated by priority to fit, ending with `and N more` and the run link:

| Forge | Documented limit | Budget |
|---|---|---|
| GitHub | none (65,536 characters is widely reported) | 60,000 characters |
| GitLab | 1,048,576 characters description, 1,000,000 note ([issues](https://docs.gitlab.com/api/issues/)) | 1,000,000 |
| Azure DevOps | 1,000,000 characters for a long text field ([object limits](https://learn.microsoft.com/en-us/azure/devops/organizations/settings/work/object-limits)) | 900,000 of HTML |

### Visibility

An issue on a public GitHub repository or a public Azure DevOps project is readable by anyone,
while code-scanning alerts on the same repository are not. The body therefore carries **counts by
default**, on every repository and project: open and accepted findings by priority, the failing
controls and the run link. `details: findings` adds each finding's location, message and fix, for
a team whose tracker is where the work is done.

GitLab issues are created **confidential** unless `item.confidential: false`, so the counts stay
with project members.

### Metadata

Each kind sets the metadata its forge offers, in the forge's own vocabulary, under `item:`, **when
it creates the item**. After that the item belongs to whoever triages it. A later write adds back a
configured label or tag that has gone missing and changes nothing else, so a reassignment or a
moved milestone survives the next run.

| Metadata | `github-issue` | `gitlab-issue` | `azure-work-item` |
|---|---|---|---|
| labels | `labels` | `labels` | `tags` |
| assignees | `assignees`, logins | `assignees`, usernames, one on Free | `assignedTo`, an identity |
| milestone | `milestone`, a title | `milestone`, a title | `iterationPath` |
| type | `type`, an organization issue type | `type`: `issue`, `incident` or `task` | `type`, a work item type |
| confidential | none | `confidential` | none |
| area | none | none | `areaPath` |
| priority | none | none | `priority`, 1 to 4 |
| other fields | none | none | `fields`, reference name to value |

- **Names, not ids.** GitHub takes a milestone number and GitLab takes user ids, so the publisher
  resolves the title (`GET …/milestones?state=all`) and each username (`GET /users?username=`). A
  name that does not resolve fails the publish and names it.
- **The tracking label is separate.** `label` finds the item and is always applied; `item.labels`
  and `item.tags` are applied beside it and never used to find anything, so changing them does not
  orphan an item.
- **GitHub drops without saying.** Labels, assignees, milestone and type are "silently dropped"
  without push access ([issues](https://docs.github.com/en/rest/issues/issues#create-an-issue)),
  so the publisher compares the created issue with the request and fails naming push access.
- **GitLab sets metadata once for a Guest.** "Guest users can only set metadata when creating an
  issue" ([permissions](https://docs.gitlab.com/user/permissions/)), which is one more reason the
  role is Planner.
- **Azure tags need a permission.** A new tag needs *Create tag definition*, and a Stakeholder in a
  private project can assign only tags that already exist
  ([tags](https://learn.microsoft.com/en-us/azure/devops/boards/queries/add-tags-to-work-items)).
- **`fields` cannot reach what Draugr owns.** Title, description, state, tags and every field with
  its own key are refused, so `fields` holds only a process's custom or optional fields.
- **Paid-tier fields are left out.** GitLab's weight, epic and iteration need Premium, and GitHub's
  issue fields need an organization that has enabled them. The live test runs on free tiers and
  could not exercise them.

## Configuration

New `PublisherConfig` fields. Existing fields keep their meaning: `repo`, `tokenEnv`, `org`,
`project`.

| Field | Kinds | Type | Default |
|---|---|---|---|
| `label` | all three | string | `draugr` |
| `branches` | all three | list of branch names or globs | the default branch |
| `details` | all three | `counts` or `findings` | `counts` |
| `item` | all three | object, per [Metadata](#metadata) | none |

`item` holds only the keys its kind reads:

| Key | Kinds | Type | Default |
|---|---|---|---|
| `labels` | `github-issue`, `gitlab-issue` | list of strings | none |
| `assignees` | `github-issue`, `gitlab-issue` | list of strings | none |
| `milestone` | `github-issue`, `gitlab-issue` | string | none |
| `type` | all three | string | GitHub none; GitLab `issue`; Azure the Bug category's default type, then `Issue`, then `Task` |
| `confidential` | `gitlab-issue` | bool | `true` |
| `tags` | `azure-work-item` | list of strings | none |
| `assignedTo` | `azure-work-item` | string | none |
| `areaPath`, `iterationPath` | `azure-work-item` | string | the project root |
| `priority` | `azure-work-item` | integer, 1 to 4 | the process default |
| `fields` | `azure-work-item` | map of field reference name to string | none |

```yaml
config:
  publishers:
    - kind: github-issue
      label: security
      item:
        labels: [triage]
        assignees: [octocat]
        milestone: Q4 hardening
    - kind: azure-work-item
      details: findings
      item:
        tags: [triage]
        areaPath: Payments\Security
        priority: 2
        fields:
          Custom.Team: Payments
```

What the rest of the registration needs, from `docs/contributing/extending/publisher.md` and the
tests that hold it:

- `builders`, `rendered` (nothing, since the body is built from `report.Data`), `local` (false).
- `distinguishes`: `repo` for the GitHub and GitLab kinds, `project` for Azure. Two entries of one
  kind against one destination would fight over the same item.
- Both schema files, with an enum or an `openStrings` entry for every new string field
  (`internal/schemagen/strictness_test.go`), and `TestSchemaCoversEveryModelField`.
- A field set on a kind that does not read it is refused by validation, not ignored.

## Failure

**A publisher that cannot deliver fails the run.** That is the existing rule
(https://github.com/draugr-dev/draugr/issues/858, https://github.com/draugr-dev/draugr/issues/462):
the verdict leads the message and the publishing error follows it. A tracker that silently stopped
updating must not look like a quiet week.

Each error names the fix.

| Condition | Message names |
|---|---|
| no token | the variable and how to map it into the job |
| GitHub 403, not a rate limit | the permission in `X-Accepted-GitHub-Permissions` ([troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api)) |
| issues disabled | GitHub 410, GitLab 403 |
| a requested label, assignee, milestone or type missing from a created issue | the token's lack of push access |
| Azure tag not created | the *Create tag definition* permission |
| a milestone or username that does not resolve | the name, and where it was looked up |
| a `fields` key Draugr owns | the key, and the `item` key that sets it |
| 404 | the resource may not exist **or** the token may not see it; all three forges answer 404 for both |

## GitHub

- **Where:** `GITHUB_API_URL`, which covers GitHub Enterprise Server as `https://HOST/api/v3`;
  repository from `GITHUB_REPOSITORY`; run link from `GITHUB_SERVER_URL`, `GITHUB_REPOSITORY` and
  `GITHUB_RUN_ID`.
- **Token:** `GITHUB_TOKEN`, with `permissions: issues: write` in the workflow. The restricted
  default grants only `contents` and `packages` read, and it is the default for new organizations
  and personal repositories. A fine-grained token needs *Issues: write*.
- **Label:** created before the first create. The docs say labels on a new issue are "silently
  dropped" without push access
  ([issues](https://docs.github.com/en/rest/issues/issues)), and label auto-creation is not
  documented. `GET …/labels/{name}`, then `POST …/labels` on 404; any 422 on the create re-reads
  the label, because `already_exists` is not a documented response.
- **Find:** `GET /repos/{o}/{r}/issues?labels=<label>&state=open`, paged by `Link`, skipping items
  with a `pull_request` key.
- **Write:** `POST …/issues`; `PATCH …/issues/{n}` with `state: closed` and `state_reason: completed`
  or `duplicate`; comments at
  `POST …/issues/{n}/comments`.
- **Limits:** 80 content-creating requests a minute and 500 an hour. GitHub Enterprise Server
  disables rate limits by default, and an administrator can enable them.

## GitLab

- **Where:** `CI_API_V4_URL`, project `CI_PROJECT_ID`.
- **Token:** `CI_JOB_TOKEN` cannot write issues or notes, and fine-grained job tokens offer only
  `READ_WORK_ITEMS` ([job token](https://docs.gitlab.com/ci/jobs/ci_job_token/)). The token is
  `GITLAB_TOKEN`, as for the merge-request publisher, and is one of:
  - a fine-grained personal access token (GitLab 19.2 and later) with *Issue: Create, Update* and
    *Issue Note: Create*, the least privilege;
  - a personal, project or group access token with the `api` scope. Project and group tokens need
    Premium on GitLab.com; on Free, a service account holds the token.
- **Role:** Planner. A Guest can create an issue and close one it authored, but cannot change
  labels on an existing issue or see a confidential duplicate somebody else created ([permissions](https://docs.gitlab.com/user/permissions/)).
- **Find:** `GET /projects/:id/issues?labels=<label>&author_username=<self>&state=opened`, paged
  by `Link`.
- **Write:** `POST /projects/:id/issues` creates missing labels as project labels;
  `PUT …/issues/:iid` with `description` or `state_event: close`; notes at
  `POST …/issues/:iid/notes`.
- **Limits:** GitLab.com allows 200 issue creations and 60 notes a minute; self-managed defaults to
  300 notes a minute and no issue limit.

## Azure DevOps

- **Where:** `SYSTEM_TEAMFOUNDATIONCOLLECTIONURI`, as `azure-pr-comment` reads it (the same value as
  `SYSTEM_COLLECTIONURI`); project `SYSTEM_TEAMPROJECT`; API version 7.1, so Azure DevOps Server
  2022.1 or later. Server 2022 RTW supports 7.0 only.
- **Token:** `SYSTEM_ACCESSTOKEN`, mapped into the step. The build identity
  (`{Project} Build Service ({Org})`, or the collection identity, which is the default) needs
  *View* and *Edit work items in this node* on the area path where items land, and *Create tag
  definition* the first time the tag is used. The build service is not a Contributor, so that
  permission is not a default. A PAT needs `vso.work_write`, and `vso.code` unless `branches:` is
  set.
- **Type:** unless `item.type` names one, the default type of `Microsoft.BugCategory`, then `Issue` (the Basic process has no
  Bug), then `Task`, checked against `workitemtypes` because a type can be renamed or disabled.
- **States by category, never by name:** close to the one state in the `Completed`
  category; an item is open when its state is in neither `Completed` nor `Removed`.
- **Find:** WIQL on `[System.Tags] CONTAINS '<label>'` and `[System.TeamProject]`, open states only,
  then `GET _apis/wit/workitems?ids=` in batches of 200. Tags are case sensitive and `CONTAINS`
  may match a substring, so tags are split on `;` and compared exactly.
- **Write:** one JSON-Patch `PATCH` per change, guarded by `{"op":"test","path":"/rev"}`.
  Comments use `7.1-preview.4`, which takes HTML; the Markdown `format` parameter exists only on
  7.2-preview on Services.
- **Limits:** on Services, 200 TSTUs per pipeline in a sliding five minutes and 10,000 REST
  updates per work item. Neither applies to Server.

## Decisions

| # | Decision | Proposal | State |
|---|---|---|---|
| 1 | Finding detail and metadata | counts by default on every repository, `details: findings` to list them; GitLab confidential by default; per-forge metadata under `item:` | agreed 2026-09-28 |
| 2 | Order of delivery | GitHub first, with the whole core; GitLab and Azure DevOps each a pull request after it | agreed 2026-09-28 |
| 3 | Which runs act | the default branch, per scope key; `branches:` adds others | agreed 2026-09-28 |
| 4 | A closed item on a failing gate | left closed; the next failing run creates a new item | agreed 2026-09-28 |
| 5 | Two open items with one marker | oldest kept, the rest closed as duplicates | agreed 2026-09-28 |
| 6 | Label | `draugr`, set by `label` | agreed 2026-09-28 |
| 7 | Azure work item type | Bug category default, then `Issue`, then `Task` | proposed |
| 8 | Live test | all three forges, on free tiers, in the live tier ([Live test](#live-test)) | agreed 2026-09-28 |

### Live test

Each forge has a sandbox the live tier writes to, and each costs nothing:

| Forge | Sandbox | Credential |
|---|---|---|
| GitHub | a repository in the `draugr-dev` organization, so `item.type` can be exercised | a fine-grained token scoped to it with *Issues: write*; `GITHUB_TOKEN` reaches only the repository running the workflow ([`GITHUB_TOKEN`](https://docs.github.com/en/actions/concepts/security/github_token)) |
| GitLab.com Free | a project in a `draugr-dev` group | a personal access token of a service user holding Planner; project access tokens need Premium on GitLab.com ([project access tokens](https://docs.gitlab.com/user/project/settings/project_access_tokens/)) |
| Azure DevOps | a private project in a free organization; Basic is free for five users ([billing](https://learn.microsoft.com/en-us/azure/devops/organizations/billing/buy-basic-access-add-users)) | an organization-scoped PAT of a Basic user, since a Stakeholder cannot create tags; global PATs stop working on 2026-12-01 ([PATs](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate)) |

An Entra service principal with workload identity federation would remove the stored Azure secret,
but needs the organization connected to an Entra tenant. It can replace the PAT later without
touching the publisher.

## Sequence

Each forge's sandbox and credential exist before its step starts.

1. **Core and `github-issue`.** `RunPublisher`, the default-branch fields in `pkg/ci`, the scope
   key, the retry changes, the body model with both renderers, and the GitHub publisher. The three
   body variants are shown and one chosen before the renderer is written. Docs, CHANGELOG, an
   `examples/` descriptor.
2. **`gitlab-issue`.**
3. **`azure-work-item`.**
4. **Dogfood, after a release containing step 1.** Replace the issue steps in `selfscan.yml`,
   `integration.yml` and the draugr.dev scan workflow with the publisher, which counts open and
   accepted findings from the report rather than deriving one from the other.

## Acceptance

Each line is a test. Unit tests run against a fake forge server per kind; every keyed test uses
**two scopes and two projects**, so one's run is shown not to touch the other's item.

- Each lifecycle row, per forge.
- Gate: an incomplete run opens with each error as a list item after the findings; `--no-gate` writes nothing and says so; a passing
  verdict closes.
- Branches: a pull-request event, a merge-request pipeline and `BUILD_REASON=PullRequest` write
  nothing and say so; a non-default branch writes nothing; `branches:` admits a listed branch and a
  glob.
- Scope: a passing `--controls sca` run leaves the `all` item open; relabeling a component leaves
  the key of a `--labels` run unchanged.
- Identity: an item with the label and no marker is untouched; two marked items leave the oldest
  open and close the other with a comment naming it.
- Writes: an unchanged finding set sends no write; a changed one sends one.
- Scanner text: a message holding `@user`, `#12`, a backtick run and a leading `/` appears inside
  a code span whose fence is longer than the run, and no body line starts with scanner text.
- Size: a report over budget ends with `and N more` and keeps the highest priorities.
- Failure: each row of the failure table produces its message; a 403 with rate-limit headers waits
  and retries; `Retry-After` on an Azure 200 delays the next request.
- Descriptor: `draugr validate`, `draugr doctor` and `draugr scan` against an `examples/`
  descriptor using each kind.
- Metadata: each `item` key reaches the create request; a second run on an item whose assignee
  and milestone a person changed leaves both, and adds back a configured label that was removed;
  a key set on a kind that does not read it fails validation.
- Details: `counts` emits no location or message; `findings` emits both.
- Body: three rendered variants shown, and one chosen, before the renderer is built.
- Closed by hand: an item closed while the gate fails is left untouched, and the next failing run
  creates a second item.
- Live, per forge: fail, pass, fail, pass against the sandbox leaves two closed items, each with
  one close comment, and no open item.

## Corrections

The issue's forge facts were checked on 2026-09-28. These differ from what it states, and the
sections above use the corrected version:

- A GitLab Guest **can** close issues it authored; it cannot change labels on an
  existing issue.
- A GitLab `api`-scoped token is not the only option; fine-grained personal access tokens can
  create and update issues from 19.2.
- Azure DevOps comments on 7.1 are preview-only (`7.1-preview.4`).
- An Azure PAT reading the default branch needs `vso.code` as well as `vso.work_write`.
- The Azure build service may be unable to create the tag, which needs *Create tag definition*.
- Azure sends `Retry-After` on a 200, not only a 429.
- The 10,000-update and TSTU limits apply to Azure DevOps Services only.
- A colocated `.md` per publisher is not a convention; `TestEveryPluginHasColocatedDocs` covers
  controllers, scanners and surveyors. Publisher docs live in the catalog, the reports and
  publishers guide, and the Saga reference, which `TestEveryPublisherIsDocumented` checks.
- The catalog states that authenticated integrations such as Jira and ServiceNow are out of scope.
  A forge issue tracker is the CI job's own forge, reached with a token the job already has or can
  be granted, so it needs no third-party account; the catalog says so when the publishers land.
