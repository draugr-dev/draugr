# Draugr documentation

Start here. The docs are grouped by what you're trying to do (loosely following the
[Diátaxis](https://diataxis.fr/) model).

## Get started
- [Quickstart](quickstart.md) — install, first scan, first survey, prioritize, gate in CI.

## Understand it (explanation)
- [Concepts](concepts.md) — the core ideas and how they fit together.
- [Pipeline](pipeline.md) — the run in detail (plan → scan → aggregate → judge → report), with
  a deep-dive on the gate.
- [Naming & control taxonomy](naming.md) — what each control means and the Norse names.
- [Glossary](glossary.md) — plain-language definitions of the security categories (SCA, SAST, …).
- [Architecture](ARCHITECTURE.md) — package layout and design.

## Reference
- [CLI reference](cli.md) — every command and flag.
- [Saga reference](saga-reference.md) — every field of `draugr.saga.yaml`.
- [Integrations catalog](integrations.md) — controllers, scanners, and surveyors (what ships today).
- [Plugin API](plugin-api.md) — the Scanner / Controller / Surveyor / Reporter interfaces.

## Draugr's building blocks

The recurring names, and where each is explained in depth:

| Term | What it is | Learn more |
|------|------------|------------|
| **Saga** | the `draugr.saga.yaml` descriptor of your app | [concepts](concepts.md#the-saga-descriptor) · [reference](saga-reference.md) |
| **Controller** | owns one security control (e.g. `sca`) | [concepts](concepts.md#controllers) |
| **Scanner** | wraps one tool, emits SARIF | [concepts](concepts.md#scanners) |
| **Surveyors — the Ravens** | discover your app's surface | [concepts](concepts.md#surveyors--the-ravens) |
| **Norn** | the policy gate (pass/fail verdict) | [pipeline](pipeline.md#5-judge--the-norn) |
| **Skald** | renders the evidence (JSON + SARIF) | [pipeline](pipeline.md#6-report--the-skald) |
| **SARIF** | the finding interchange format everything normalizes to | [concepts](concepts.md#sarif-everywhere) |
