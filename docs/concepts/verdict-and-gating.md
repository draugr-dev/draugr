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

- **Plan**, expand enabled controllers × components into scan jobs (deterministic order).
- **Scan**. Run jobs with bounded concurrency; results normalized to SARIF.
- **Aggregate**, merge and **deduplicate** each control's findings, then **correlate**: a flaw
  two scanners both found is counted once, with both accounts kept.
- **Judge (the gate)**. Apply policy thresholds to produce a pass/fail verdict per control
  and overall.
- **Report**. Render the run: a human summary to stdout (console by default, or `markdown`),
  plus machine formats (`json`, `sarif`); `-o/--output` writes `report.json` and
  `results.sarif`.

## Verdict & exit code

The gate produces `pass` / `fail`. `draugr scan` exits non-zero on `fail`, so it gates a
pipeline directly.

**A run has one gate, and there are two questions it could ask.** By default it asks what
**band** a finding landed in for the component it was found in, failing on `P1`. That band folds
in the exposure and criticality the descriptor declares, which is context no scanner can compute.

`--fail-on` (or `config.gate.failOn`) asks the other question instead: what **severity** the
scanner gave the flaw on its own terms, with optional per-control overrides. Setting both is
refused rather than combined, because a verdict with two possible reasons cannot be read back to
the rule that produced it.

Which of the two catches more depends on the component, so neither is the stricter one. On a
component that declares nothing, `P1` means critical or high, the same findings `--fail-on high`
catches, arrived at by asking the other question. On a component declared `restricted` and
`supporting`, nothing reaches `P1` at all, and the descriptor is saying that a flaw there does not
stop a release.

### A scan that checked nothing is not a pass

A descriptor that enables no control, or none whose surface its components carry, plans no work.
Every stage after that behaves exactly as it would for a spotless application, no findings, no
failures, `PASS`, and the two are indistinguishable in the output.

The wrong reading is the likelier one: a descriptor reaches that state by being unfinished, or by
being generated with [`draugr survey`](../reference/cli.md#draugr-survey), which describes a
surface without enabling anything to check it. So the run reports that nothing ran, and the
verdict fails.

A descriptor that asks only for an SBOM is exempt. It enables no control by design, and still
produces the evidence it was asked for.

### A control that couldn't run is not a pass

If a scanner is missing, exits badly, or a control can't be planned, that control **checked less
than it was asked to**, so an empty report from it isn't evidence of anything. Draugr fails the run
and says which control it was:

```
CONTROLS
  sca  ERROR  did not run
       trivy-fs: exec: "trivy": executable file not found in $PATH

draugr: scan incomplete: sca could not run (use --allow-scan-errors to accept partial results)
```

This matters most in CI, where a scanner failing to provision is the common failure and a
warning in the log goes unread. A green build from a check that never ran is the one outcome a
gate must not produce.

Pass `--allow-scan-errors` for best-effort scanning. The run then passes on findings alone. The
errored control is still reported either way; the flag buys a passing exit code, not silence.

### A surface nobody looked at *does* pass, so it is reported instead

The third way a `PASS` can mean less than it appears is the one Draugr deliberately does **not**
fail on. A component can declare images, or hosts, while the controls that examine them are off.
Every enabled control runs, finds nothing wrong, and the verdict is a clean pass over a surface
that was never opened.

Unlike the two above, this is not treated as an error, because a narrow descriptor is a legitimate
thing to have: scanning a repository you do not own for committed secrets and nothing else is a
real use, and a tool that failed the run would be failing a decision somebody made on purpose. A
gate that objects to intent is one people learn to work around.

So it is reported rather than enforced. Every scan says what it did not look at:

```
NOT CHECKED
  api hosts   3 controls off: dast, headers, tls
  api images  1 control off: images
```

[`draugr doctor`](../reference/cli.md#draugr-doctor-sagayaml) says the same thing **before** the
scan, which is usually where you want to hear it, and `--fail-on-uncovered` turns it into a
failure for a descriptor that is meant to be complete:

```bash
draugr doctor draugr.saga.yaml --fail-on-uncovered && draugr scan draugr.saga.yaml
```

The answer comes from one place, so the scan, doctor and the
[MCP server](../guides/ai-agents-mcp.md) cannot tell you different things about the same
descriptor.

`dast` is never in the suggestion, and that is deliberate: it sends attack traffic at a live
service, and enabling that because something noticed the service exists is not a decision Draugr
gets to make for you.

## Understanding the report

A finding is described on **three related axes**. Knowing which is which removes most confusion:

| Axis | Values | What it is | Where it shows |
|------|--------|------------|----------------|
| **Priority** | P1 · P2 · P3 · P4 | Draugr's headline ranking: **severity × the component's exposure & criticality**. "What to fix first." | the band counts under the verdict, and the order of "fix first" |
| **Severity** | critical · high · medium · low | Normalized impact. From the **CVSS score** when a scanner provides one (`security-severity`), else derived from the finding's level (error→high, warning→medium, note→low). | the per-control counts and the "fix first" severity column |
| **Level** | error · warning · note | The raw **SARIF** value each scanner maps into, the lowest common denominator. | the machine formats (`--format json`/`sarif`) and the gate (`--fail-on`) |

So the same CVE can be **critical** severity but **P3** priority on an internal tool, or **P1** on a
public, business-critical service. The human report (console/markdown/html) speaks **priority +
severity**; `level` stays for the gate and machine output. The console view is **color-coded** on a
terminal (verdict, priorities, severities) and honors `NO_COLOR`.

A worked example:

```text
DRAUGR  FAIL  draugr-demo 1.0  5.238s

 P1 67 P2 102 P3 82 P4 18

CONTROLS
  iac      FAIL   P1 4 P2 5 P3 12
  images   FAIL   P1 40 P2 90 P3 77
  sast     FAIL   P1 7 P2 6
  sca      FAIL   P1 9 P2 8 P3 1
  secrets  FAIL   P1 1

COMPONENTS
  api       FAIL   P1 67 P2 102 P3 79
  platform  FAIL   P3 3 P4 18

FIX FIRST  top 10 of 269, by priority
  Priority  Severity  Rule            Scanner  Location                Upgrade
  P1        critical  CVE-2019-20477  trivy    app/requirements.txt:4  PyYAML 5.1 → 5.2
            command execution through python/object/apply constructor in FullLoader
  P1        high      KSV-0014        trivy    deploy/pod.yaml:8
            Root file system is not read-only
```

The **Components** block is where the classification pays off. `api` and `platform` share the `iac`
control and the same rules, and the same findings land at P1/P2 on one and P3/P4 on the other,
because one is internet-facing and business-important and the other is neither. Severity did not
change; the consequence of it did.

Every block above answers in bands, which is what the gate is set in and what the fix list is
ordered by. What a scanner called a flaw is on the finding's own row, where the judgment about it
was made.

## Observability & security posture

Structured logs (`log/slog`), plus OpenTelemetry traces and metrics (opt-in via `OTEL_*`). Logs and
span attributes never carry secrets. Draugr's own CI enforces `govulncheck`, `gosec`, and
`golangci-lint`. It meets the bar it holds others to.

## The report says which gate produced the verdict

A verdict means nothing without the policy behind it, and the policy can be changed by whoever
runs the scan. So the report states it:

```
Gate: fails on critical severity, except licenses on critical.
```

- **A gate somebody chose is stated in the default view.** Not because it is looser, but because
  a pass means something different under each question, and nothing else on the page says which
  one was asked.
- **The default says nothing until asked.** A reader who configured nothing already has it, and
  spending a line on it every run buries the cases that are news.
- **`--no-gate` is stated loudest**, and says what it changes: the verdict is reported and the
  command still exits 0, so anything reading the exit code is told the opposite of what the report
  says.
- **`--evidence` states the gate whatever it is**, including the default, because "the default" is
  an answer only when the report gives it rather than leaving it to be assumed.

- **`report.json` carries it too**, in a `gate` block, alongside the threshold each control was
  actually judged against. A verdict read by a machine, or on a dashboard somewhere else, has the
  same claim on its reason as one read in a terminal, and the descriptor that would otherwise
  answer for it does not travel with the report. See
  [reports and publishers](../guides/reports-and-publishers.md#what-produced-the-run).

This is the same discipline as [suppression](../reference/saga-schema.md): a decision that changes
what the verdict covers stays visible, rather than disappearing into an exit code.
