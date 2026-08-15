# Adding a control

A **control** is one security question Draugr can answer about a component — “are my dependencies
vulnerable?”, “does this repository contain secrets?”. It is a **controller** (which decides what
applies and aggregates the results) plus at least one **scanner** (which runs a tool).

Read [scanner.md](scanner.md) first: the scanner half of this work is that page, and this one
covers only what is different when the question itself is new.

## Is it really a new control?

Two tools answering the same question are two scanners on one control. Ask what a user would put
in the descriptor and what they would do with the answer:

- If the finding belongs in the same list as an existing control's, ranked by the same model,
  it is **another scanner**.
- If it needs its own threshold, its own gate line, and would read as a category of its own in a
  report, it is **a control**.

A control that duplicates another's findings under a second name makes every report harder to
read and every suppression ambiguous.

## 1. The controller

`internal/controllers/<control>.go`, implementing three methods.

**`Info()`** returns `{Name, Scope}`. `ScopeComponent` unless the control is genuinely
project-wide, as `infrastructure` is.

**`Plan(model, comp)`** returns one `plugin.ScanJob` per resource. This is where the
one-job-per-repository rule lives:

```go
for _, repo := range comp.Repositories {
	jobs = append(jobs, plugin.ScanJob{
		// … one job per repository, not one per component
		CacheKey: plugin.ComputeCacheKey(/* … */),
	})
}
```

- Return `nil, nil` for a nil component rather than panicking.
- Set `CacheKey` with `plugin.ComputeCacheKey`. A job with no cache key is re-run every time; a
  job with the *wrong* key returns another job's results.
- Use `resolveScanners` to select scanners rather than naming one. Even if there is only one
  today, hardcoding it is what makes the second one silently unreachable later.

**`Aggregate(reports)`** merges with `sarif.Merge(...)` and folds `.Counts()` into the `Summary`.
Escalate severity here when the tool under-rates for your control's purpose — a committed secret
is an error whatever the tool called it — and say in the doc that you do, because a severity that
does not match the tool's own output will otherwise read as a bug.

## 2. The scanner

Follow [scanner.md](scanner.md) in full. Register both halves:

```go
// internal/builtins/builtins.go
reg.RegisterController(controllers.NewYourControl())
reg.RegisterScanner(scanners.NewYourTool())
```

## 3. Wire the control into the descriptor

A new control is a new key under `config.controllers`, so:

```bash
go generate ./pkg/saga/...
go test ./internal/schemagen/
```

Then check that `draugr validate` accepts a descriptor enabling it, and that `draugr controls`
lists it. Both schemas — Saga and fragment — are generated from the live registry.

## 4. Document it

- `internal/controllers/<control>.md` and `internal/scanners/<tool>.md`, colocated.
- Rows in [`docs/reference/catalog.md`](../../reference/catalog.md) for both.
- The control's entry in [`docs/reference/glossary.md`](../../reference/glossary.md), in
  plain language — a reader meeting `dast` for the first time needs the concept, not the flag.
- A `learn/` page on the website if the control is a concept the reader may not know.

## 5. Test it

Everything in [scanner.md](scanner.md#7-test-it), plus, for the controller:

- `Info()` — name and scope.
- `Plan` with **two repositories** → two jobs, the right scanner, cache keys set and *distinct*.
  With one repository, a per-component value and a per-repository value are indistinguishable.
- `Plan` with a nil component.
- `Aggregate` — the counts, and any escalation you do.
- `Aggregate` with no reports.
- The registration test in `internal/builtins`.

## 6. Prove it end to end

```bash
draugr validate <your>.saga.yaml
draugr doctor  --saga <your>.saga.yaml
draugr scan    <your>.saga.yaml
```

Point it at a fixture that genuinely triggers a finding, and confirm the verdict and the exit code
are what you expect — including that a **missing tool reports an error rather than a pass**, which
is the failure mode this whole design exists to prevent.

## 7. Consider the self-scan

If the control applies to this Go repository, enable it in `.draugr/self.saga.yaml`. Note that the
self-scan runs the latest **release**, not `main`, so a descriptor field that does not exist in a
release yet will fail: dogfooding a new control is always two pull requests, either side of a
release.

## 8. Finish

The [definition of done](README.md#definition-of-done), and the two out-of-repository
destinations — the website and the demo — described at the end of [scanner.md](scanner.md#9-finish).
