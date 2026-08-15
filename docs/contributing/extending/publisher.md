# Adding a publisher

A **publisher** delivers rendered artifacts somewhere: a file, a code-scanning endpoint, a sticky
comment on a pull request.

```go
type Publisher interface {
	Kind() string
	Publish(ctx context.Context, artifacts []report.Artifact) error
}
```

Everything is in `pkg/publish`. `azure_pr_comment.go` and `gitlab_mr_comment.go` are the models —
follow one closely, because the discipline in them is most of the value.

## Publisher or reporter?

If the destination **accepts an upload**, it is a publisher. If the destination reads a **file the
CI runner collects**, it is a [reporter](reporter.md) plus a line in a CI template. GitLab's
security reports are reporters for exactly this reason: there is no endpoint to upload to.

Deciding wrongly produces a publisher that appears to work and delivers nothing.

## 1. Write it

```go
func newYourPublisher(cfg saga.PublisherConfig) (Publisher, error) { /* … */ }
```

The constructor **validates**, and this is where most of the care goes.

### Resolve from the environment; never take a secret from the descriptor

The Saga is a file people commit. A token belongs in an environment variable, named by the
descriptor at most. Default everything else from the CI environment too — project, pull-request
number, API base — so that using the publisher requires no configuration at all in the place it
normally runs.

Prefer reusing existing `PublisherConfig` fields over adding new ones.

### Skip loudly, fail loudly, and tell them apart

Two different situations, two different behaviours:

- **Not applicable** — not running in that CI system, or not in a pull request. Return a
  `skipPublisher` with a reason. It logs what it skipped and why, so a user who expected a comment
  can see the reason rather than an absence.
- **Applicable but misconfigured** — a missing token, a bad project. That is an **error**, and its
  message must name the fix.

“The flag did nothing and said nothing” is the failure this design exists to prevent.

### Name the credential trap, if the platform has one

Where a platform hands the job a token that cannot do the thing, say so explicitly. GitLab's
`CI_JOB_TOKEN` is read-only on the Notes API, so the missing-credential error names it and says a
Project Access Token with `api` scope is required. Without that, a user gets an unexplained 401
from a variable the platform set for them and never asked for.

### Follow pagination when looking for your own marker

A sticky comment works by finding the marker it left last time. If the listing is paginated and
you read only the first page, a marker further down means posting a **duplicate every run**
instead of updating one comment. Match against user comments rather than system notes, too, so a
bot's note can never be mistaken for yours.

### Escape path parameters correctly

Where a platform identifies a project by a path, the separators have to survive as `%2F` or the
request addresses something else entirely. Use `url.PathEscape`: it encodes them, and so does
`url.QueryEscape`, but query escaping writes a space as `+`, which a path does not mean.

Test with a **nested** path. A single-segment one needs no escaping at all, so it passes under any
choice and proves nothing.

### Read error bodies with a limit

`io.LimitReader(resp.Body, 2048)`. A remote error should improve the message, not become it.

## 2. Register it

```go
// pkg/publish/publish.go
var builders = map[string]func(saga.PublisherConfig) (Publisher, error){
	// …
	"your-kind": newYourPublisher,
}
```

Then, and none of these are optional:

- **`pkg/publish/publish_test.go`** — `TestKinds` asserts the exact list.
- **`pkg/saga/draugr.saga.schema.json` and `draugr.saga-fragment.schema.json`** — the `kind`
  `anyOf` is **hand-maintained**; `internal/schemagen` does not touch publishers. A kind missing
  here is one an editor rejects while Draugr accepts it.
- **`internal/cli/diff.go`** — `diffPublisherKind()` if the publisher is the right default for a CI
  system, plus its case in `diff_test.go`.

## 3. Document it

The publishers table in [`docs/reference/catalog.md`](../../reference/catalog.md),
[`docs/guides/reports-and-publishers.md`](../../guides/reports-and-publishers.md),
[`docs/reference/saga-schema.md`](../../reference/saga-schema.md),
[`docs/reference/cli.md`](../../reference/cli.md) where `--publish` names the available
publishers, and [`docs/guides/pr-diff.md`](../../guides/pr-diff.md) for a comment publisher.
Plus a user-first `CHANGELOG.md` entry.

## 4. Test it

Against a fake HTTP server:

- Creating a comment when none exists; **updating** when the marker is found.
- The marker on a **second page** — the case that turns an update into a duplicate.
- Each skip condition, with its reason.
- Each missing-credential case, and that the message names the fix.
- Path escaping with a **nested** project path.
- A remote error surfaces, with its body included and truncated.

## 5. Prove it against the real platform

A fake server proves your client; it cannot prove you understood the API. Point it at a real
project:

```bash
GITLAB_CI=true CI_API_V4_URL=https://gitlab.com/api/v4 \
CI_PROJECT_ID=<id> CI_MERGE_REQUEST_IID=<iid> GITLAB_TOKEN=<pat> \
./bin/draugr diff base.sarif head.sarif --publish
```

Run it **twice**: the second run must edit the first comment, not add one. Then delete the comment
and confirm a third run recreates it. Also confirm the no-token path prints the message naming the
fix rather than a bare 401.

If the publisher is used by a CI template, remember that templates install the latest **release** —
so a template exercising a new flag lands after a release containing it.
