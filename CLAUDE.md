# Working on Draugr

Orientation for AI coding assistants, and a reasonable first read for humans too.
[CONTRIBUTING.md](CONTRIBUTING.md) has the mechanics; this file is the *why* behind them, which
is what keeps them from being applied mechanically.

## What Draugr is

A **security and compliance qualification** tool. You describe your application in a declarative
descriptor — the **Saga** — and Draugr infers which checks apply, runs them, normalizes every
result to one schema, and returns a deterministic gated verdict with evidence.

The shape of a run, which is also the shape of the code:

```
Saga  →  controllers  →  scanners  →  SARIF  →  Norn  →  verdict + evidence
        (what applies) (run a tool) (one schema) (policy)
```

- **Controllers** decide *what to check* for a component and aggregate the results.
- **Scanners** run an external tool (Trivy, Semgrep, Gitleaks, Nuclei, Syft…) and normalize its
  output.
- **SARIF 2.1.0** is the finding currency. Everything converges on it before anything is judged.
- **The Norn** applies policy — thresholds, priorities, suppressions — and produces the verdict.

## Layout

`pkg/` is the public API; treat changes there as breaking until proven otherwise. `internal/` is
implementation and can move freely.

| Package | What lives there |
|---|---|
| `pkg/saga` | The descriptor: repositories, images, hosts, config, exclusions |
| `pkg/plugin` | The extension SDK — `Scanner`, `Controller`, `Surveyor`, and shared types |
| `pkg/sarif` | The finding model, plus merge and deduplication |
| `pkg/engine` | Expands a Saga into scan jobs and orchestrates the run |
| `pkg/norn` | Evaluates results against policy to produce a verdict |
| `pkg/report` | Renders a result: console, markdown, HTML, JUnit, JSON, SARIF |
| `internal/controllers`, `internal/scanners` | The built-in controls and the tools behind them |
| `internal/builtins` | Where both get registered |

A new control is a controller plus a scanner, registered in `internal/builtins`. Copy the shape
of an existing pair — `sca` + `trivy-fs` for a repository tool, `images` + `trivy` for one that
scans a named artifact.

## Before you open a PR

```bash
make gate    # fmt, vet, lint, race tests + coverage, govulncheck
```

CI runs the same checks, so a local failure is a CI failure you caught early. Two traps:

- Lint with a **fresh** `GOLANGCI_LINT_CACHE`. A warm cache produces false passes that then fail
  in CI: `GOLANGCI_LINT_CACHE=$(mktemp -d) golangci-lint run ./...`
- Keep your Go toolchain on the **latest 1.26.x patch**. `govulncheck` reports stdlib
  vulnerabilities fixed in patch releases, and CI always resolves the newest one.

## Design principles

These are the opinions the codebase rests on. A change that contradicts one needs an argument,
not just passing tests.

**Nothing fails silently.** A control whose scanner is missing reports an error, not a pass. A
flag you passed either does something or explains why it didn't. A swallowed error, an ignored
option, `continue-on-error` in CI — these all produce the same thing, which is a green tick that
means nothing. Prefer a loud failure to a quiet one every time.

**Suppress, don't delete.** An excluded finding stays in the report marked suppressed, carrying
the reason someone gave for excluding it. A finding that vanishes is indistinguishable from one
that was never made — and the question an auditor asks is never "did the scanner run", it's "who
decided this was acceptable, and when".

**Deterministic core.** Detection, severity, the gate and the evidence never involve inference.
They have to return the same answer on the same input and be explainable to someone who wasn't
there. Language models are useful at the edges — explaining a finding, phrasing a fix — and not
in the parts that have to be reproducible.

**Human-readable by default.** A person is the default consumer. Machine formats — JSON logs,
`--format json|sarif` — are opt-in behind a flag.

**Execute third-party tools; don't link or bundle them.** A tool run as a subprocess keeps its
licence its own. This is deliberate and constrains how integrations are written.

**Severity is not priority.** Severity rates a flaw in the abstract. Priority (P1–P4) folds in
the component's declared exposure and criticality — context no scanner can compute, because it
isn't in the code.

## Definition of done

A user-facing change isn't finished until, **in the same pull request**:

1. **Reference docs** are updated — `docs/reference/saga-schema.md` for descriptor changes,
   `docs/reference/cli.md` for flags.
2. **A new controller, scanner or surveyor has its colocated `.md`** next to the code, plus a row
   in [`docs/reference/catalog.md`](docs/reference/catalog.md) linking to it. This is enforced by
   `TestEveryPluginHasColocatedDocs`, which walks the real registry — so registering a plugin is
   what triggers the requirement.
3. **`CHANGELOG.md`** has an entry under `## [Unreleased]`, written **user-first**: what you can
   now do and what changed for you, not which functions moved.
4. **Tests** cover the new behaviour. The bar is **≥90% on changed packages**; pure glue and
   unreachable OS-error branches are exempt, and coverage theatre helps nobody.

Documentation follows [Diátaxis](https://diataxis.fr/) — tutorial, how-to, reference, or
explanation. Knowing which one you're writing prevents most documentation problems.

## Changing what `draugr scan` prints

The console layout is quoted in several files under `docs/`, captured into the demo screenshot
the README shows and into the fragment the website's home page carries, and quoted in posts
there. None of them notice when it changes, so it's pinned by a golden test:

```bash
go test ./pkg/report -run TestConsoleGolden   # fails if the layout moved
go test ./pkg/report -update                  # accept the new layout
make examples                                 # real output from the demo sandbox, to paste
```

If the golden fails, its message lists everything that needs refreshing. Please work through it
rather than only regenerating the golden — a stale example in the docs costs a reader more than
it costs us.

## Conventions

- **Markdown:** write issue references as full URLs
  (`https://github.com/draugr-dev/draugr/issues/N`). GitHub doesn't auto-link `#N` inside files.
  Don't linkify ordinals ("the number-one complaint") or `#anchors`.
- **Commits:** explain the *why*, not just the what.
- **Go:** Cobra for the CLI, `log/slog` for logging, OpenTelemetry for traces and metrics. Doc
  comments on exported symbols (revive enforces this).
- **Never log secrets** — not in messages, not in span attributes, not in error strings.
- Bundling a few small related changes into one PR is fine. Focused matters more than singular.

## Useful to know

- **The self-scan runs the latest _release_, not `main`.** Draugr gates its own CI with itself,
  using the published binary — which is how users run it. A new Saga field therefore can't be
  used in `.draugr/self.saga.yaml` until a release containing it exists, so dogfooding a new
  feature is always two pull requests, either side of a release.
- **[`draugr-demo`](https://github.com/draugr-dev/draugr-demo)** is a deliberately vulnerable
  sandbox used by the docs examples and the demo screenshot. Its findings are the point; don't
  fix them.
- Security issues in Draugr itself go through [SECURITY.md](SECURITY.md), privately — not a
  public issue.
