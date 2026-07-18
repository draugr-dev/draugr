# Draugr documentation

Start here. The docs are grouped by section; every published page carries a `section`
frontmatter and is rendered by the docs site. This index and the `contributing/` pages have no
`section` and are not published — they live here for readers browsing the repo.

## Getting started
- [Install](getting-started/install.md) — install Draugr and the scanners its controls need, and verify the download.
- [Quickstart](getting-started/quickstart.md) — from zero to a verdict: describe, scan, focus, discover.
- [Write your first Saga](getting-started/first-saga.md) — a gentle walkthrough of authoring `draugr.saga.yaml`.

## Core concepts
- [The Saga](concepts/saga.md) — the `draugr.saga.yaml` descriptor.
- [Controls & scanners](concepts/controls-and-scanners.md) — controllers, scanners, SARIF, and caching.
- [Prioritization](concepts/prioritization.md) — exposure × criticality × severity → P1–P4.
- [Surveyors — the Ravens](concepts/surveyors.md) — discovery that writes the Saga for you.
- [Verdict & gating](concepts/verdict-and-gating.md) — the pipeline, the gate, and exit codes.

## Guides
- [Use in CI with the GitHub Action](guides/github-action.md) — the first-party action and its inputs.
- [Publish to GitHub code scanning](guides/code-scanning.md) — the native `github` publisher.
- [Gate PRs on new findings](guides/pr-diff.md) — `draugr diff` and sticky PR comments.
- [Reports & publishers](guides/reports-and-publishers.md) — render many formats, deliver anywhere.
- [Caching & performance](guides/caching-and-performance.md) — content-hash cache and parallelism.
- [Classify components](guides/classify-components.md) — set `exposure` and `criticality`.

## Reference
- [CLI reference](reference/cli.md) — every command and flag.
- [Saga schema](reference/saga-schema.md) — every field of `draugr.saga.yaml`.
- [Integrations catalog](reference/catalog.md) — controllers, scanners, and surveyors (what ships today).
- [Security glossary](reference/glossary.md) — plain-language definitions (SCA, SAST, DAST, …).

## Trust & operations
- [Verifying releases](trust-and-operations/verifying-releases.md) — cosign, SLSA provenance, SBOMs.
- [Updating Draugr & tools](trust-and-operations/updating.md) — `self-update` and `tools install`.

## Contributing
- [Architecture](contributing/architecture.md) — package layout and design.
- [Plugin API](contributing/plugin-api.md) — the Scanner / Controller / Surveyor / Reporter / Publisher interfaces.
- [Pipeline](contributing/pipeline.md) — the run stage by stage, with a deep-dive on the gate.
- [Naming & control taxonomy](contributing/naming.md) — what each control means and the Norse names.

## Building blocks

The recurring names, and where each is explained in depth:

| Term | What it is | Learn more |
|------|------------|------------|
| **Saga** | the `draugr.saga.yaml` descriptor of your app | [concept](concepts/saga.md) · [schema](reference/saga-schema.md) |
| **Controller** | owns one security control (e.g. `sca`) | [controls & scanners](concepts/controls-and-scanners.md#controllers) |
| **Scanner** | wraps one tool, emits SARIF | [controls & scanners](concepts/controls-and-scanners.md#scanners) |
| **Surveyor** | discovers your app's surface | [surveyors](concepts/surveyors.md) |
| **Gate** | applies policy to produce the pass/fail verdict | [verdict & gating](concepts/verdict-and-gating.md) |
| **Report** | renders the run (human summary + JSON/SARIF evidence) | [verdict & gating](concepts/verdict-and-gating.md#the-pipeline) |
| **SARIF** | the finding interchange format everything normalizes to | [controls & scanners](concepts/controls-and-scanners.md#sarif-everywhere) |
