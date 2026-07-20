---
title: Verdict & gating
description: The pipeline, the pass/fail verdict, and how it gates a CI pipeline.
section: Core concepts
order: 50
---

# Verdict & gating

A Draugr run is a pipeline that turns your descriptor (your `draugr.saga.yaml`) into a
pass/fail verdict plus audit-ready evidence. This page covers how the run flows and how the
verdict gates a pipeline; for the stage-by-stage internals see the
[pipeline deep-dive](../contributing/pipeline.md).

## The pipeline

```
Describe ─► Plan ─► Scan ─► Aggregate ─► Judge ─► Report
 (Saga)   (jobs) (SARIF)  (per control) (gate)  (verdict)
```

- **Plan** — expand enabled controllers × components into scan jobs (deterministic order).
- **Scan** — run jobs with bounded concurrency; results normalized to SARIF.
- **Aggregate** — merge and **deduplicate** each control's findings.
- **Judge (the gate)** — apply policy thresholds to produce a pass/fail verdict per control
  and overall.
- **Report** — render the run: a human summary to stdout (console by default, or `markdown`),
  plus machine formats (`json`, `sarif`); `-o/--output` writes `report.json` and
  `results.sarif`.

## Verdict & exit code

The gate produces `pass` / `fail`. `draugr scan` exits non-zero on `fail`, so it gates a
pipeline directly. The failure threshold is configurable (`--fail-on`, default `error`),
with optional per-control overrides, plus a component-aware priority gate
(`--fail-on-priority`). The run fails if either gate trips.

## Understanding the report

A finding is described on **three related axes** — knowing which is which removes most confusion:

| Axis | Values | What it is | Where it shows |
|------|--------|------------|----------------|
| **Priority** | P1 · P2 · P3 · P4 | Draugr's headline ranking: **severity × the component's exposure & criticality**. "What to fix first." | the `Priorities:` line and the order of "fix first" |
| **Severity** | critical · high · medium · low | Normalized impact. From the **CVSS score** when a scanner provides one (`security-severity`), else derived from the finding's level (error→high, warning→medium, note→low). | the per-control counts and the "fix first" severity column |
| **Level** | error · warning · note | The raw **SARIF** value each scanner maps into — the lowest common denominator. | the machine formats (`--format json`/`sarif`) and the gate (`--fail-on`) |

So the same CVE can be **critical** severity but **P3** priority on an internal tool, or **P1** on a
public, business-critical service. The human report (console/markdown/html) speaks **priority +
severity**; `level` stays for the gate and machine output. The console view is **color-coded** on a
terminal (verdict, priorities, severities) and honors `NO_COLOR`.

A worked example:

```text
Draugr — FAIL   (draugr-demo 0.0.0)

Priorities:  P1 21   P2 25   P3 13   P4 0

Controls:
  iac      FAIL  4 high  5 medium  12 low
  sca      FAIL  3 critical  6 high  8 medium  1 low
  secrets  FAIL  1 high

Fix first:
  P1  critical  9.8  CVE-2019-20477  sca  app/requirements.txt:4
  P1  high      8.0  KSV-0014        iac  deploy/pod.yaml:8
```

## Observability & security posture

Structured logs (`log/slog`), plus OpenTelemetry traces and metrics (opt-in via `OTEL_*`).
Logs and span attributes never carry secrets. Draugr's own CI enforces `govulncheck`,
`gosec`, and `golangci-lint` — it meets the bar it holds others to.
