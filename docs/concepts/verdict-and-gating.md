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

### A scan that checked nothing is not a pass

A descriptor that enables no control, or none whose surface its components carry, plans no work.
Every stage after that behaves exactly as it would for a spotless application — no findings, no
failures, `PASS` — and the two are indistinguishable in the output.

The wrong reading is the likelier one: a descriptor reaches that state by being unfinished, or by
being generated with [`draugr survey`](../reference/cli.md#draugr-survey), which describes a
surface without enabling anything to check it. So the run reports that nothing ran, and the
verdict fails.

A descriptor that asks only for an SBOM is exempt — it enables no control by design, and still
produces the evidence it was asked for.

### A control that couldn't run is not a pass

If a scanner is missing, exits badly, or a control can't be planned, that control **checked
less than it was asked to** — so an empty report from it isn't evidence of anything. Draugr
fails the run and says which control it was:

```
Controls:
  sca  ERROR  did not run
       trivy-fs: exec: "trivy": executable file not found in $PATH

draugr: scan incomplete: sca could not run (use --allow-scan-errors to accept partial results)
```

This matters most in CI, where a scanner failing to provision is the common failure and a
warning in the log goes unread. A green build from a check that never ran is the one outcome a
gate must not produce.

Pass `--allow-scan-errors` for best-effort scanning — the run then passes on findings alone.
The errored control is still reported either way; the flag buys a passing exit code, not
silence.

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
Draugr — FAIL   (draugr-demo 1.0)

Priorities:  P1 67   P2 102   P3 82   P4 18

Controls:
  iac      FAIL   4 high  5 medium  12 low
  images   FAIL   9 critical  40 high  90 medium  77 low
  sast     FAIL   7 high  6 medium
  sca      FAIL   3 critical  6 high  8 medium  1 low
  secrets  FAIL   1 high

Components:
  api       FAIL   P1 67  P2 102  P3 79  iac, images, sast, sca, secrets
  platform  FAIL   P3 3  P4 18  iac

Fix first (top 10 of 269, by priority):
  Priority  Severity  Score  Rule            Control  Scanner  Location
  P1        critical  9.8    CVE-2019-20477  sca      Trivy    app/requirements.txt:4
            PyYAML: command execution through python/object/apply constructor in FullLoader
  P1        high      8.0    KSV-0014        iac      Trivy    deploy/pod.yaml:8
            Root file system is not read-only
```

The **Components** block is where the classification pays off. `api` and `platform` share the
`iac` control and the same rules, and the same findings land at P1/P2 on one and P3/P4 on the
other — because one is internet-facing and business-important and the other is neither. Severity
did not change; the consequence of it did.

## Observability & security posture

Structured logs (`log/slog`), plus OpenTelemetry traces and metrics (opt-in via `OTEL_*`).
Logs and span attributes never carry secrets. Draugr's own CI enforces `govulncheck`,
`gosec`, and `golangci-lint` — it meets the bar it holds others to.
