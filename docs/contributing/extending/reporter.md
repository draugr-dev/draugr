# Adding a reporter

A **reporter** renders a finished run into one format. It decides nothing: the verdict, the
priorities and the suppressions are all settled by the time it is called.

```go
type Reporter interface {
	Format() string
	Render(w io.Writer, d Data) error
}
```

Everything is in `pkg/report`. `gitlab.go` is a good model for a format defined by somebody else's
schema; `markdown.go` for one that is ours to design.

## 1. Write it

```go
func (r yourReporter) Format() string { return "your-format" }

func (r yourReporter) Render(w io.Writer, d Data) error { /* … */ }
```

`Data` carries the whole run: results, summary, the component metadata, and `scanErrors`.

**Use `scanErrors`.** A control that could not run must not render as a clean scan. Whatever your
format's equivalent is — a status field, a failure element — set it, or the format quietly reports
success for work that never happened.

## 2. Register it

```go
// pkg/report/report.go
var reporters = map[string]Reporter{
	// …
	"your-format": yourReporter{},
}
```

Then decide **how it is delivered**, which is a real distinction and not a detail:

- **`StreamFormats`** — formats whose natural destination is somewhere output goes: `console`,
  `markdown`, `json`, `sarif`. These are what `--format` accepts.
- **`documentFormats`** — formats produced as files, like `junit` and GitLab's reports. A user
  passing `--format` for one of these gets an error telling them where the format *does* go, rather
  than silence.

Getting this wrong is a flag that appears to work and produces nothing.

## 3. Give it a filename

`formatMeta` in `pkg/report/artifact.go` maps the format to the file it is written as. Where the
consumer is somebody else's tool, use **their** conventional name — `gl-sast-report.json`, not one
of ours — so a pipeline written from their documentation finds the file.

## 4. Validate against the real schema

If the format belongs to another system, vendor its published schema under `pkg/report/testdata/`
and validate your output against it in a test.

This matters most where you cannot watch it render: a schema test is the verifiable half of
“this is correct”, and it catches the field you renamed by hand far more reliably than reading
does.

## 5. Severity, priority, and which one to carry

Draugr distinguishes **severity** (how bad the flaw is in the abstract) from **priority** (how
much it matters here, folding in the component's exposure and criticality). Carry whichever one
the consumer's own machinery keys on:

- A system whose **policies** read severity should receive severity, or those policies misfire.
- A reviewer-facing “what do I fix” list with no policy engine behind it should receive priority,
  because that ordering is what Draugr exists to produce.

Document the mapping as a table in the guide for that format. A reader comparing two systems' output
will otherwise assume a bug.

## 6. The console format is pinned

If you change what `draugr scan` prints, a golden test fails on purpose:

```bash
go test ./pkg/report -run TestConsoleGolden   # fails if the layout moved
go test ./pkg/report -update                  # accept the new layout
make examples                                 # real output from the demo sandbox, to paste
```

The failure message lists everything that needs refreshing — including files in the **website
repository**, which nothing here can check. Work through the list rather than only regenerating
the golden: the layout is quoted in the README, several `docs/` pages, the demo screenshot and
posts on the site, and none of them notice when it changes.

## 7. Test it

- The format renders and round-trips, where round-tripping is meaningful.
- A run with a scan error renders as failed.
- A run with no findings renders as a valid empty document, not an empty file.
- Schema validation, if the format is someone else's.
- Rendering is deterministic — sort anything you iterate over a map to produce.

## 8. Document it

The format list in [`docs/reference/cli.md`](../../reference/cli.md), the reporters table in
[`docs/reference/catalog.md`](../../reference/catalog.md), and
[`docs/guides/reports-and-publishers.md`](../../guides/reports-and-publishers.md). Plus a
user-first `CHANGELOG.md` entry.
