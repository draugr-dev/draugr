---
title: The Saga
description: The draugr.saga.yaml descriptor — a security bill of materials for a running app.
section: Core concepts
order: 10
---

# The Saga (descriptor)

Draugr turns a description of your app into trustworthy, audit-ready security evidence. The
starting point is the **Saga**.

`draugr.saga.yaml` is the source of truth — a *security bill of materials for a running
application*. It lists your **components** (repositories, images, hosts, infrastructure) and
which **controls** must pass. You write what you know; Draugr works out the rest.

## Why a descriptor at all

The alternative is wiring each scanner into each pipeline by hand. That works until you have
more than a few services, and then the pipelines drift: one repo runs secret scanning and its
neighbour doesn't, a threshold is stricter in one place than another, and nobody can answer
"which checks actually ran against this release" without reading a dozen CI files.

A descriptor moves that decision out of the pipeline and into a file that lives with the app:

- **One place to look.** What the app is made of, and what must pass, in a file you review and
  diff like any other.
- **Checks follow the surface.** Declare an image and image scanning applies; declare a host and
  the HTTP header and TLS controls do. There's no second list of which scanner runs where to
  keep in step with the first.
- **Context a scanner cannot compute.** How exposed a component is, and what its failure costs,
  are not in the code. Declaring them is what lets Draugr turn a pile of "criticals" into an
  ordered list.
- **The evidence knows what it covered.** A run's report is anchored to the descriptor, so the
  auditor's question — what was in scope — has an answer that isn't "whatever CI happened to do
  that day".

## Anatomy

```yaml
release:                      # required — what is being qualified
  name: acme-platform
  version: "1.4.0"

config:                       # optional — controls, thresholds, reports, publishers
  controllers:
    secrets: { enabled: true }

components:                   # the app's parts
  - name: web
    exposure: public          # how reachable it is
    criticality: critical     # what its failure costs
    repositories:
      - url: https://github.com/acme/web.git
    images:
      - image: registry.example.com/acme/web:1.4.0
        digest: sha256:…
    hosts:
      - url: https://acme.example.com

references: []                # optional — links to manual or human-run controls
```

Every field is covered in the [Saga reference](../reference/saga-schema.md). The four that
shape a run most are below.

### `release`

What this run qualifies. `version` is required — it's what the evidence is filed under.

### `components`

One entry per logical part of the app, each listing whatever surface applies:
`repositories`, `images`, `hosts`, `infrastructure`. All are optional and a component may have
only one. A Kubernetes cluster with no code of its own is a perfectly good component with
nothing but an `infrastructure` entry.

Surface is what drives the plan. Draugr expands each enabled control across the components it
applies to, so adding an image to a component is what makes image scanning run against it.

### `exposure` and `criticality`

The two axes of [prioritization](prioritization.md), and the clearest reason a descriptor beats
a pipeline flag. **Exposure** is how reachable a component is — likelihood. **Criticality** is
what its failure costs — impact. Neither is in the source code, so no scanner can infer them,
and without them a scanner can only ever tell you severity in the abstract.

The same CVE is act-now on a public, business-critical gateway and backlog on a restricted
internal tool. That distinction is yours to declare, and it's what turns a wall of findings into
a short list. Both are optional; a component may stay unclassified.
[`draugr classify`](../reference/cli.md#draugr-classify-sagayaml) walks you through setting them.

### `config`

Project-wide settings: which controllers run and how they're tuned, the
[gate](verdict-and-gating.md) thresholds, exclusions, reports and publishers, SBOM generation,
and `allowEffects` for scanners that would otherwise change something in your environment. A
component's own `controllers` block overrides the project default for that component.

## Exclusions are not deletions

An excluded finding stays in the report, **marked suppressed, carrying the reason someone gave**.
It doesn't count toward the verdict, and it doesn't disappear.

This is deliberate. A finding that vanishes is indistinguishable from one that was never made,
and the question an auditor asks is never "did the scanner run" — it's "who decided this was
acceptable, and when". See [`config.exclude`](../reference/saga-schema.md#configexclude).

## Writing one

Three ways in, in rough order of how much you already know:

| Start with | When | What you get |
|---|---|---|
| **Nothing** | You want output now | `draugr scan .` runs `sca`, `secrets`, `sast` and `iac` against a repository with no descriptor at all |
| **[`draugr init`](../reference/cli.md#draugr-init-dir)** | You have a repo and want a starting point | Detects the stack and pre-fills sensible controls — Go adds `gosec`, a Dockerfile adds an `images` stub |
| **[`draugr survey`](surveyors.md)** | Something you already run can be enumerated — today a Kubernetes cluster or a GitHub org | [Surveyors](surveyors.md) enumerate the surface and write the components for you |

Zero-config mode is a way to start, not a way to finish: it scans a single repository, and it
has no way to know a component's exposure or criticality, so it cannot prioritize. The
descriptor is what upgrades a scan into a qualification.

## How Draugr finds it

`draugr scan` takes a **file** — the Saga to run — or a **directory**, which triggers
zero-config mode against that repository. With no argument at all it uses the current directory.

```bash
draugr scan                     # zero-config, current repo
draugr scan draugr.saga.yaml    # run the descriptor
```

Any string value may reference an environment variable with `${{ VAR_NAME }}`. Loading **fails
fast if one is unset**, rather than scanning on with an empty value.

## Keeping it honest

A descriptor is only worth what its accuracy is worth, and two things protect that:

- **Editor support.** A `# yaml-language-server:` line gives you autocomplete, hover
  documentation and validation as you type — see
  [editor support](../reference/saga-schema.md#editor-support-autocomplete-hover-docs-validation).
- **Re-survey.** `draugr survey` against a live cluster or org adds what has appeared
  since, so the descriptor tracks reality instead of drifting away from it.

## Going deeper

- [Saga reference](../reference/saga-schema.md) — every field, with examples
- [Your first Saga](../getting-started/first-saga.md) — write one end to end
- [Controls & scanners](controls-and-scanners.md) — what the descriptor resolves to
- [Prioritization](prioritization.md) — how `exposure` and `criticality` become P1–P4
- [Verdict & gating](verdict-and-gating.md) — how a run turns into pass or fail
- [Surveyors](surveyors.md) — let discovery write it for you
