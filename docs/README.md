# Draugr documentation

Start here. The docs are grouped by section; every published page carries a `section`
frontmatter and is rendered by the docs site. This index and the `contributing/` pages have no
`section` and are not published — they live here for readers browsing the repo.

## Getting started
- [Install](getting-started/install.md) — install Draugr and the scanners its controls need, and verify the download.
- [Quickstart](getting-started/quickstart.md) — from zero to a verdict: describe, scan, focus, discover.
- [Write your first Saga](getting-started/first-saga.md) — a gentle walkthrough of authoring `draugr.saga.yaml`.

## Core concepts
- [Principles](concepts/principles.md) — what Draugr optimizes for: great UX, human-readable output, and a low learning curve.
- [The Saga](concepts/saga.md) — the `draugr.saga.yaml` descriptor.
- [Controls & scanners](concepts/controls-and-scanners.md) — controllers, scanners, SARIF, and caching.
- [Prioritization](concepts/prioritization.md) — exposure × criticality × severity → P1–P4.
- [Surveyors](concepts/surveyors.md) — discovery that writes the Saga for you.
- [Verdict & gating](concepts/verdict-and-gating.md) — the pipeline, the gate, and exit codes.

## Guides
- [Use in CI with the GitHub Action](guides/github-action.md) — the first-party action and its inputs.
- [Use in CI with Azure Pipelines](guides/azure-pipelines.md) — the pipeline, the Tests tab, and a sticky PR comment.
- [Use in CI with GitLab](guides/gitlab-ci.md) — the template, a sticky MR comment, and GitLab's own reports.
- [Publish to GitHub code scanning](guides/code-scanning.md) — the native `github` publisher.
- [Gate PRs on new findings](guides/pr-diff.md) — `draugr diff` and sticky PR comments.
- [See findings in your editor](guides/findings-in-your-editor.md) — SARIF as inline diagnostics in VS Code and JetBrains.
- [Use Draugr from an AI coding assistant](guides/ai-agents-mcp.md) — the MCP server, and why it beats letting an assistant improvise.
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
- [Scope and disclaimer](trust-and-operations/disclaimer.md) — what a passing verdict does and
  doesn't mean, why licence findings aren't legal advice, and whose terms the scanners carry.

## Contributing
- [Architecture](contributing/architecture.md) — package layout and design.
- [Plugin API](contributing/plugin-api.md) — the Scanner / Controller / Surveyor / Reporter / Publisher interfaces.
- [Pipeline](contributing/pipeline.md) — the run stage by stage, with a deep-dive on the gate.
- [Naming & control taxonomy](contributing/naming.md) — what each control means and the Norse names.
- [The cache architecture](contributing/cache.md) — the three caches, how a key is derived, and what a hit does not promise.

### Extending Draugr — how-to guides
- [Start here](contributing/extending/README.md) — which piece you need, and the rules that apply to all of them.
- [Add a scanner](contributing/extending/scanner.md) — run a different tool for a control that already exists.
- [Add a control](contributing/extending/control.md) — a controller plus a scanner, for a question Draugr can't yet answer.
- [Add a tool](contributing/extending/tool.md) — let `draugr tools install` provision it, pinned and verified.
- [Add a surveyor](contributing/extending/surveyor.md) — discover components and write the Saga.
- [Add a reporter](contributing/extending/reporter.md) — render the result in another format.
- [Add a publisher](contributing/extending/publisher.md) — deliver the result somewhere.

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

<!-- CI path filter verified 2026-07-27: this docs-only change should skip the Go jobs. -->
