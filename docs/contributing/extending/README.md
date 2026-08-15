# Extending Draugr

How to add a new piece to Draugr, one page per kind of piece. These are how-to guides: they
assume you have read [the architecture](../architecture.md) and [the plugin
API](../plugin-api.md), and they tell you what to do in what order.

## Which one am I adding?

| I want to… | Add a | Guide |
|---|---|---|
| run a different tool for a control that already exists (a second SCA scanner, another SAST engine) | **scanner** | [scanner.md](scanner.md) |
| check something Draugr does not check at all (a new kind of risk) | **control** — a controller *and* a scanner | [control.md](control.md) |
| let `draugr tools install` provision a tool | **tool entry** | [tool.md](tool.md) |
| discover components automatically from somewhere (a cloud account, a forge, a cluster) | **surveyor** | [surveyor.md](surveyor.md) |
| render the result in another format | **reporter** | [reporter.md](reporter.md) |
| deliver the result somewhere (an API, a comment, a bucket) | **publisher** | [publisher.md](publisher.md) |

If you are unsure between a scanner and a control: a **control** is a *question*
(“are my dependencies vulnerable?”), a **scanner** is one *way of answering it*. Two tools that
answer the same question are two scanners on one control, not two controls — that is what lets
their findings be ranked together by one risk model.

## What every one of them has in common

These apply whichever guide you follow, and most of them are checked mechanically.

### Nothing fails silently

The single rule most likely to be violated by accident. A control whose scanner is missing must
report an **error**, not a pass. An option nobody read, a swallowed error, a tool whose exit code
was ignored — each produces a green tick that means nothing, and a green tick that means nothing
is worse than a red one, because nobody investigates it.

Concretely, in the places it comes up:

- A tool that exits non-zero **on findings** must be told not to (`--exit-code 0`, `--exitwith 0`
  and their equivalents). Severity is the control's job; the findings belong in the report, not
  in the exit status.
- A tool that exits non-zero because it **could not run** must surface as an error.
- A configuration key you accept must do something, or say why it did not.

### Execute third-party tools; do not link, bundle, or host them

Running a tool as a subprocess keeps its licence its own. Linking or bundling can make Draugr a
derivative work. Distribution is copyleft's other trigger, so Draugr names an upstream URL rather
than serving anyone else's bytes — including from a cache or a mirror.

`draugr tools install` downloads pinned, verified releases because those have been reviewed. For
anything not reviewed, name what is needed and let the operator install it; the report then says
`external`, which is true. See [tool.md](tool.md).

### Read the licence, the terms and the privacy notice — all three, from the source

Before an integration merges, not after. Not the API overview, not a summary, not what the issue
that scoped the work assumed. Free tiers carry conditions that are easy to miss when a key is
issued in thirty seconds — *non-commercial* is a common one, and it decides whether a user may
run the control at all.

Write what you established into the colocated doc. Two parts of this are enforced:

- `TestEveryToolDocStatesItsTerms` requires the statement in every scanner and surveyor doc.
- `TestDisclosingScannersDocumentWhatTheySend` requires a `## What is sent` section from any
  scanner declaring the `disclosure` effect.

**If you cannot identify the document that governs the tier being used, the integration does not
ship.** A vendor owned by a larger company will point at the parent's terms, and those may govern
a contracted enterprise service while saying nothing about the free tier a connector actually
uses. Infer nothing from how the API behaved once: behaviour changes without notice, the contract
is the durable statement, and the useful question is always *which* contract.

### A colocated doc, and a row in the catalog

Every controller, scanner and surveyor has a `.md` next to its code, plus a linking row in
[`docs/reference/catalog.md`](../../reference/catalog.md). `TestEveryPluginHasColocatedDocs` walks
the real registry, so registering the plugin is what triggers the requirement — you cannot forget
it and still have a green build.

A plugin with no documentation compiles and passes its own tests; nothing looks wrong until
someone goes looking for the docs.

### Tests take two of whatever there can be two of

A component may hold several repositories, and Draugr plans **one job per repository, run
concurrently**. Anything that collapses a per-repository value into a per-component one is
invisible with one repository and silently picks a winner with two — a report that describes
whichever job finished last.

So wherever a controller plans jobs, a scanner derives a name, or a report groups anything:
**one repository proves the loop runs; two prove it does not collapse.** Two components sharing a
repository is the other half of the same shape, and worth a thought whenever something is keyed
on a repository rather than a component.

### Prove it with a descriptor, not only a test

Unit tests build `plugin.Config` directly and never go through descriptor validation, so a whole
class of failure passes a full `make gate` and appears the moment a real Saga is loaded. Write a
descriptor that uses your new piece and run:

```bash
draugr validate <your>.saga.yaml
draugr doctor --saga <your>.saga.yaml
draugr scan <your>.saga.yaml
```

The per-kind guides list what specifically tends to be missing at each of those three steps.

### Definition of done

A user-facing change is not finished until, **in the same pull request**:

1. **Reference docs** — [`docs/reference/saga-schema.md`](../../reference/saga-schema.md) for
   descriptor changes, [`docs/reference/cli.md`](../../reference/cli.md) for flags.
2. **The colocated `.md`** and its catalog row.
3. **`CHANGELOG.md`** under `## [Unreleased]`, written **user-first**: what you can now do, not
   which functions moved.
4. **Tests** at ≥90% on changed packages. Pure glue, type-only packages and unreachable OS-error
   branches are exempt — coverage theatre helps nobody, and a package left below the bar is worth
   saying out loud in the pull request rather than padding.

And before you open it:

```bash
make gate    # fmt, vet, lint, race tests + coverage, govulncheck
```

Lint with a **fresh** `GOLANGCI_LINT_CACHE` — a warm cache produces passes that then fail in CI —
and keep your Go toolchain on the latest 1.26.x patch, because `govulncheck` reports stdlib
vulnerabilities fixed in patch releases and CI always resolves the newest.

## Where things live

| Path | What |
|---|---|
| `pkg/plugin` | the interfaces: `Scanner`, `Controller`, `Surveyor`, and the shared types |
| `internal/scanners` | the built-in scanners, each with its `.md` |
| `internal/controllers` | the built-in controllers, each with its `.md` |
| `internal/surveyors` | the built-in surveyors, each with its `.md` |
| `internal/builtins` | where controllers, scanners and surveyors are registered |
| `internal/tools` | the provisioning catalog: pinned releases, Python and npm packages |
| `pkg/report` | reporters — how a result is rendered |
| `pkg/publish` | publishers — where a rendered result is delivered |
| `pkg/saga` | the descriptor, its validation, and the generated JSON Schemas |
