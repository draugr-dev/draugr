# Concepts

Draugr turns a description of your app into trustworthy, audit-ready security evidence.
The pieces:

## The Saga (descriptor)

`draugr.saga.yaml` is the source of truth — a *security bill of materials for a running
application*. It lists your **components** (repositories, images, hosts, infrastructure)
and which **controls** must pass. You write what you know; Draugr does the rest. See the
[Saga reference](saga-reference.md).

## Controllers

A **controller** owns one **security control** (e.g. `images`, and — on the roadmap —
`sast`, `opensource`, `dast`, `headers`, `certificates`, `infrastructure`, `threats`).
It plans the work for the components it applies to and aggregates the results. Controllers
are either **project-scoped** or **component-scoped**.

> Implemented today: **`images`**.

## Scanners

A **scanner** wraps a single security tool and normalizes its output to **SARIF**. Most
tools are integrated declaratively via a *tool adapter* — describe how to invoke the tool
and Draugr runs it and parses its SARIF. The first built-in scanner is **Trivy** (images).

## Surveyors — "the Ravens"

**Surveyors** discover your app's surface and return Saga fragments, so the descriptor can
write itself. Built-in: **`k8s-images`** (unique images in a cluster/namespace) and
**`github-org-repos`** (repositories in a GitHub org). Named for Odin's ravens, Huginn and
Muninn, who fly the world and report back.

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
- **Report (the Skald)** — render a JSON evidence summary and merged SARIF.

## SARIF everywhere

Every finding is normalized to **SARIF 2.1.0** (the OASIS standard). That means plugins
interoperate, and results push straight into GitHub / Azure DevOps / GitLab security
dashboards.

## Content-hash caching

Each scan job has a cache key derived from its inputs (scanner, version, target identity,
config). With a cache enabled (`--cache-dir`), an unchanged target is never re-scanned —
the "cheap at scale" pillar. Cache entries have a configurable TTL because new
vulnerabilities can affect an unchanged artifact.

## Verdict & exit code

The Norn produces `pass` / `fail`. `draugr scan` exits non-zero on `fail`, so it gates a
pipeline directly. The failure threshold is configurable (`--fail-on`, default `error`),
with optional per-control overrides.

## Observability & security posture

Structured logs (`log/slog`), plus OpenTelemetry traces and metrics (opt-in via `OTEL_*`).
Logs and span attributes never carry secrets. Draugr's own CI enforces `govulncheck`,
`gosec`, and `golangci-lint` — it meets the bar it holds others to.
