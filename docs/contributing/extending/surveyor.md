# Adding a surveyor

A **surveyor** discovers what exists and writes it down as a Saga fragment. It answers “what do we
even have?” — the question that precedes every scan, and the one most likely to be answered wrongly
from memory.

```go
type Surveyor interface {
	Info() SurveyorInfo
	Survey(ctx context.Context, scope SurveyScope) (saga.Fragment, error)
}
```

Surveyors live in `internal/surveyors`. `github_org_repos.go` and `gitlab_group_projects.go` are
the models for a forge; `k8s_cluster.go` and `k8s_images.go` for a cluster.

## 1. Write it

```go
func NewGitLabGroupProjects() plugin.Surveyor { /* … */ }

func (s gitlabGroupProjects) Info() plugin.SurveyorInfo {
	return plugin.SurveyorInfo{
		Name:     "gitlab-group-projects",
		Provides: []plugin.TargetKind{plugin.TargetRepository},
		ConfigSchema: json.RawMessage(configSchema),
	}
}
```

`Survey` returns a `saga.Fragment` — usually one component per discovered thing, each carrying its
repositories with a URL and a revision.

### Paginate

Every list API paginates, and every one of them defaults to a page size smaller than a real
account. Follow the pages to the end. A survey that reads the first page silently describes a
subset of the estate as though it were the estate, and the omission is invisible in the output:
what you get back is a valid fragment, just a short one.

### Say when the answer is partial

The most valuable thing a surveyor can do is admit what it could not see. An unauthenticated
survey of a forge returns only public repositories — a perfectly successful call that omits
everything private. Warn:

```go
// github_org_repos.go
slog.Warn("surveyed GitHub without a token — public repositories only; "+
	"private ones are not in this descriptor. Set GITHUB_TOKEN to include them",
	"org", org, "repositories", len(repos))
```

The user is about to write this fragment into a descriptor and trust it. A quiet subset is the
one failure they will not check for.

### Credentials come from the environment

Read a token from the scope config or an environment variable — never require it to be written
into a descriptor, which is a file people commit.

## 2. Register it

```go
// internal/builtins/builtins.go — SurveyorRegistry()
reg.Register(surveyors.NewGitLabGroupProjects())
```

## 3. Expose it on the CLI

`internal/cli/survey.go`, mirroring the existing subcommands (`draugr survey github repos`).
`--fragment` and `--no-exposure` come free from the shared path.

## 4. Document it

A colocated `internal/surveyors/<name>.md` and a row in
[`docs/reference/catalog.md`](../../reference/catalog.md), both enforced by
`TestEveryPluginHasColocatedDocs`. Surveyor docs must state license and terms just as scanner docs
do (`TestEveryToolDocStatesItsTerms`) — a surveyor talks to somebody's API, so what that API's
terms permit is part of what you are shipping.

If the survey sends anything anywhere, say what.

## 5. Test it

- `Info()` — name and provided target kinds.
- The fragment shape from a recorded API response: components, repositories, revisions.
- **Pagination**, with a fake returning two pages. One page proves the parser works; two prove the
  loop does.
- The unauthenticated path, including that the warning is emitted.
- An API error surfaces as an error rather than an empty fragment. An empty estate and a failed
  call must not look the same.

## 6. Prove it

Run it against a real account, and check the fragment it writes is one `draugr validate` accepts:

```bash
draugr survey <platform> <thing> --fragment out.saga.yaml
draugr validate draugr.saga.yaml
```

Then confirm the count matches what the platform's own UI says. That comparison is the whole point
of the exercise, and it is the one thing a unit test cannot do for you.
