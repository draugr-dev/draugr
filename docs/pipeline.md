# The Draugr pipeline — stage by stage

A Draugr run is a pipeline. You describe your app; Draugr turns that into a pass/fail
verdict plus audit-ready evidence. This document explains each stage, what it consumes and
produces, and how to configure it.

```
        ┌──────────┐
        │  Survey  │  (optional) the Ravens discover surface → Saga fragments
        └────┬─────┘
             ▼
  Describe ─► Plan ─► Scan ─► Aggregate ─► Judge ─► Report ─► Publish
   (Saga)   (jobs) (SARIF)  (per control) (Norn)  (Skald)  (sinks)
```

Stages map to packages: `saga`, `engine` (plan + scan + aggregate), `norn` (judge),
`report` + `skald` (report), `surveyor` (survey).

---

## 0. Survey (optional) — *the Ravens*

**In:** a scope (a Kubernetes cluster/namespace, a GitHub org). **Out:** a Saga, or
fragments merged into one.

Discovery surveyors ("the Ravens") enumerate your app's surface so you don't have to write
the descriptor by hand. `draugr survey --k8s-images --github-org <org> -o draugr.saga.yaml`.
Skip this stage entirely if you maintain the Saga yourself. See `concepts.md`.

## 1. Describe — the Saga

**In:** `draugr.saga.yaml`. **Out:** a validated in-memory model.

The Saga lists your **components** (repositories, images, hosts, infrastructure) and which
**controls** are enabled. Loading it: parses YAML, substitutes `${{ VAR }}` from the
environment (comments are ignored), and validates (required fields, unique component
names). See `saga-reference.md`.

## 2. Plan

**In:** the model + the registry of controllers. **Out:** a list of scan jobs.

The engine expands **enabled controllers × components** into concrete scan jobs. A control
runs only when enabled — globally under `config.controllers`, or per component. Controllers
are either **project-scoped** (run once) or **component-scoped** (run per component). Jobs
are produced in deterministic (name) order, and each job carries a **cache key** derived
from its inputs. You can inspect the plan without running it.

## 3. Scan

**In:** scan jobs. **Out:** SARIF per control.

Jobs run with **bounded concurrency** (default: number of CPUs, tunable with `-j/--jobs`).
Before fan-out, each distinct scanner is **prewarmed** once (e.g. Trivy's vuln DB), and
identical concurrent jobs (same scanner+target+config) are collapsed to a single scan via
in-run **singleflight** (counted as `deduped` in stats). Each job resolves its scanner and
runs it; every scanner normalizes output to **SARIF**. If a **cache** is
enabled (`--cache-dir`), a job whose cache key already has a stored result is served from
cache instead of re-scanning — unchanged targets cost nothing. Scan errors are collected
(they don't abort the whole run) and reported alongside successful results.

## 4. Aggregate

**In:** all SARIF for a control. **Out:** one merged, deduplicated report per control.

Each controller merges its scanners' outputs and **deduplicates** findings by fingerprint,
so the same issue reported by two tools (or two overlapping scans) appears once. It also
produces a severity summary (error/warning/note counts) used by the next stage.

## 5. Judge — *the Norn*

**In:** the per-control reports + a policy. **Out:** a verdict (`pass`/`fail`).

The Norn decides a release's fate. See the deep-dive below.

## 6. Report — *the Skald*

**In:** the run result + the verdict. **Out:** evidence artifacts.

The report stage renders through a `Reporter` (`pkg/report`): to stdout it prints a **console**
summary by default (or `markdown`/`json`/`sarif` via `--format`). The `json`/`sarif` formats are
backed by the Skald (release, verdict, per-control counts, run stats; and a **merged SARIF**
across all controls). `-o/--output <dir>` additionally writes `report.json` and `results.sarif`.

## 7. Publish

**In:** the evidence artifacts. **Out:** results delivered where they're needed.

Because results are SARIF, they push straight into GitHub / Azure DevOps / GitLab security
dashboards. The `scan` command's **exit code** is itself a publish channel: non-zero on a
`fail` verdict gates a CI pipeline directly. *(Native publish sinks, e.g. uploading SARIF
to GitHub code scanning, are on the roadmap.)*

---

## Deep-dive: how the Norn works

The Norn (`pkg/norn`) converts findings into a decision. It is intentionally simple and
declarative today (severity thresholds); a richer policy language can follow.

### Severity ranking

Every finding has a SARIF **level**, ranked:

| Level | Severity |
|-------|:--------:|
| `error` | 3 |
| `warning` | 2 |
| `note` | 1 |
| `none` | 0 |

### The policy

```go
type Policy struct {
    FailOn         sarif.Level            // default threshold (zero value ⇒ error)
    PerControl     map[string]sarif.Level // optional per-control overrides
    FailOnPriority string                 // optional component-aware priority gate (e.g. "P1")
}
```

- **`FailOn`** is the least-severe level that fails the gate. Default is `error` (via the
  `--fail-on` flag).
- **`PerControl`** overrides the threshold for a named control (e.g. be stricter on
  `images`, more lenient on `sast`).

### The decision

For each control the Norn takes its merged report's **highest** severity and compares it
to the applicable threshold:

> A control **fails** when its highest finding is **at or above** the threshold *and* it
> has at least one finding. An empty report always passes.

The **overall verdict fails if any control fails.** Each control's outcome carries its
verdict, highest severity, the threshold applied, and severity counts — so the evidence
shows exactly *why* it passed or failed.

### Worked examples (default threshold = `error`)

| Control findings | Threshold | Control verdict |
|---|---|---|
| 2 errors, 5 warnings | `error` | **fail** (has an error) |
| 0 errors, 5 warnings | `error` | pass (nothing at/above error) |
| 5 warnings | `warning` | **fail** (warning meets threshold) |
| no findings | any | pass |

### Configuring it

The gate is driven by `--fail-on` (a severity level) and, optionally, `--fail-on-priority`
(a component-aware priority band) on `draugr scan`:

```bash
draugr scan draugr.saga.yaml                       # fail on error (default)
draugr scan draugr.saga.yaml --fail-on warning     # stricter: warnings fail too
draugr scan draugr.saga.yaml --fail-on-priority P1 # also fail on any P1 finding
```

The run fails if **either** gate trips. Because a finding's priority already folds in its
component's `exposure` and `criticality`, `--fail-on-priority` gates per component without a
per-component threshold — see [prioritization](concepts.md#prioritization-what-to-fix-first).
Richer policy (waivers/exemptions, OPA/Rego) is planned; it'll be expressed in the Saga so
the gate travels with the app.

### Verdict → exit code

`draugr scan` prints the report (console by default; `--format markdown|json|sarif`) and
**exits non-zero on `fail`**, so the Norn's verdict directly gates CI — no extra scripting.
