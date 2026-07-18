---
title: Verdict & gating
description: The pipeline, the Norn's pass/fail verdict, and how it gates a CI pipeline.
section: Core concepts
order: 50
---

# Verdict & gating

A Draugr run is a pipeline that turns your Saga into a pass/fail verdict plus audit-ready
evidence. This page covers how the run flows and how the verdict gates a pipeline; for the
stage-by-stage internals see the [pipeline deep-dive](../contributing/pipeline.md).

## The pipeline

```
Describe ─► Plan ─► Scan ─► Aggregate ─► Judge ─► Report
 (Saga)   (jobs) (SARIF)  (per control) (Norn)  (Skald)
```

- **Plan** — expand enabled controllers × components into scan jobs (deterministic order).
- **Scan** — run jobs with bounded concurrency; results normalized to SARIF.
- **Aggregate** — merge and **deduplicate** each control's findings.
- **Judge (the Norn)** — apply policy thresholds to produce a pass/fail verdict per control
  and overall. The Norns decide fate; here, a release's.
- **Report (the Skald)** — render the run through a `Reporter`: a human summary to stdout
  (console by default, or `markdown`), plus machine formats (`json`, `sarif`); `-o/--output`
  writes `report.json` and `results.sarif`.

## Verdict & exit code

The Norn produces `pass` / `fail`. `draugr scan` exits non-zero on `fail`, so it gates a
pipeline directly. The failure threshold is configurable (`--fail-on`, default `error`),
with optional per-control overrides, plus a component-aware priority gate
(`--fail-on-priority`). The run fails if either gate trips.

## Observability & security posture

Structured logs (`log/slog`), plus OpenTelemetry traces and metrics (opt-in via `OTEL_*`).
Logs and span attributes never carry secrets. Draugr's own CI enforces `govulncheck`,
`gosec`, and `golangci-lint` — it meets the bar it holds others to.
