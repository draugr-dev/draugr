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

**Execute third-party tools; don't link, bundle, or host them.** Three clauses, one distinction
applied three times — the line between *using* somebody else's software and *taking
responsibility for it*.

- **Exec, don't bundle.** A tool run as a subprocess keeps its license its own. Linking or
  bundling can make Draugr a derivative work; a subprocess does not.
- **Point, don't host.** Copyleft's other trigger is *distribution* — ship a GPL binary and you
  owe corresponding source, and AGPL extends that to serving it over a network. Naming an
  upstream URL is an index, like a Homebrew formula. Serving the bytes is distribution, and the
  license attaches to us. This applies to caches and mirrors too, which is where it will be
  tempting.
- **Tell, don't fetch** — for anything we have not reviewed. `draugr tools install` downloads
  pinned, verified releases *because we vouched for them*. For a tool we have not, name what is
  needed and let the operator install it; the report then says `external`, which is true.

This is deliberate and constrains how integrations are written.

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
4. **Tests** cover the new behavior. The bar is **≥90% on changed packages**; pure glue and
   unreachable OS-error branches are exempt, and coverage theater helps nobody.

Documentation follows [Diátaxis](https://diataxis.fr/) — tutorial, how-to, reference, or
explanation. Knowing which one you're writing prevents most documentation problems.

## Before any third-party integration ships

**Read the license, the terms of use, and the privacy notice. All three, from the source, before
the connector merges.** Not the API overview, not a summary, not what the issue that scoped the
work assumed.

This is a rule because assuming has been wrong every time it has been tried. An issue described
one feed as the free, permissive default with an attribution requirement: authentication had since
become mandatory, free access was limited to not-for-profit use with commercial use routed through
a separate licensee, and no attribution requirement existed. Three wrong facts, all discoverable in
one page.

What has to be established, and written into the colocated doc:

- **License** — of the tool, if we exec one. Exec keeps it theirs; linking or bundling does not.
- **Terms of use** — what the free tier permits. *Non-commercial* is common and easy to miss when
  a key is issued in thirty seconds, and it decides whether a user may run the control at all.
- **Privacy and data handling** — what the other party receives, keeps, and shares. This is the
  half that has no technical signal: an integration that uploads a repository looks, in code,
  much like one that fetches a database.

Two of these are enforced mechanically, because they are checkable and a rule people remember is
a rule people forget: `TestEveryToolDocStatesItsTerms` requires the statement in every scanner and
surveyor doc, and `TestDisclosingScannersDocumentWhatTheySend` requires a `## What is sent` section
from any scanner declaring the `disclosure` effect.

**If you cannot identify the document that governs the tier we are using, the integration does not
ship.** Finding *a* contract is not the same as finding *the* one. A vendor owned by a larger
company will point at the parent's terms, and those may govern a contracted enterprise service
while saying nothing about the free tier a connector actually uses — a document that opens
"effective when Customer clicks to accept" is not the one binding somebody with a free API key.

Infer nothing from how the API behaved once. Behavior changes without notice; the contract is the
durable statement, and the useful question is always *which* contract.

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

## What this repository says about Draugr

It describes the tool, not the business around it. World-readable, so a roadmap that names what
is sold elsewhere reads as a list of things deliberately withheld — and a reader deciding whether
to adopt an open-source scanner is not helped by knowing which capability is reserved.

Out-of-scope is stated by the **technical reason** it is out of scope: what the capability would
need that a CLI running in someone's pipeline should not have — a service holding secrets, memory
of previous runs, knowledge of other teams. That reason is true, useful, and survives any change
to how the project is funded.

Third-party commercial facts are fine and sometimes necessary: Semgrep's commercial edition,
VirusTotal's non-commercial terms. `make public-scope` (in `make gate`) checks tracked files.
**It cannot see issue bodies**, which are equally public — screen those by hand.

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
