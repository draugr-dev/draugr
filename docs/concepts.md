# Concepts

Draugr turns a description of your app into trustworthy, audit-ready security evidence.
The pieces:

## The Saga (descriptor)

`draugr.saga.yaml` is the source of truth — a *security bill of materials for a running
application*. It lists your **components** (repositories, images, hosts, infrastructure)
and which **controls** must pass. You write what you know; Draugr does the rest. See the
[Saga reference](saga-reference.md).

## Controllers

A **controller** owns one **security control**. It plans the work for the components it
applies to and aggregates the results. Controllers are either **project-scoped** or
**component-scoped**.

> Implemented today: **`images`**, **`sca`**, **`secrets`**, **`sast`**, **`iac`**, **`headers`**.
> On the roadmap: `dast`, `tls`, `sbom`, `infrastructure`, `threats`. See the
> [integrations catalog](integrations.md) or run `draugr controls`.

## Scanners

A **scanner** wraps a single security tool and normalizes its output to **SARIF**. Most
tools are integrated declaratively via a *tool adapter* — describe how to invoke the tool
and Draugr runs it and parses its SARIF. Built-in today: **Trivy** (`images`, `sca`, `iac`),
**Gitleaks** (`secrets`), **Semgrep** (`sast`, with opt-in **gosec** for Go components), and a
**native HTTP-headers** scanner (`headers`).

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
- **Report (the Skald)** — render the run through a `Reporter`: a human summary to stdout
  (console by default, or `markdown`), plus machine formats (`json`, `sarif`); `-o/--output`
  writes `report.json` and `results.sarif`.

## Prioritization: what to fix first

Severity isn't priority. A `scan` can return a wall of "high" findings, but which one you
fix first depends on **where it lives**. Declare two attributes on a component and Draugr
ranks every finding into a band **P1–P4**:

- **`exposure`** (`public` → `authenticated` → `internal` → `restricted`) — how reachable the
  component is. This drives *likelihood*.
- **`criticality`** (`critical` → `important` → `supporting`) — the business impact if it
  fails. This drives *impact*.

A finding's **normalized severity** (from its CVSS score, or its SARIF level, or a
control floor) combines with the component's `exposure × criticality` through two small
lookup matrices to yield the priority. So the *same* CVE is P1 on a public, business-critical
gateway and P3 on an internal dev tool — same finding, different risk.

**Exploitability enrichment (optional).** Severity can be raised by real-world signals before
ranking: a CVE on CISA **KEV** (Known Exploited Vulnerabilities — confirmed exploited) becomes
critical, and a CVE at/above an **EPSS** (Exploit Prediction Scoring System) threshold is
bumped one band. Supply the data with `--kev`/`--epss` (offline, bring-your-own files).

- **Focus:** `--min-priority P2` lists only the findings worth acting on now
  (P1 = act now · P2 = this cycle · P3 = backlog · P4 = track).
- **Gate:** `--fail-on-priority P1` fails the build on any P1 — component-aware gating with no
  per-component config.
- A component left **unclassified** is treated as high-risk, so nothing slips silently.

## SARIF everywhere

Every finding is normalized to **SARIF 2.1.0** (the OASIS standard). That means plugins
interoperate, and results push straight into GitHub / Azure DevOps / GitLab security
dashboards.

## Content-hash caching

Each scan job has a cache key derived from its inputs (scanner, version, target identity,
config). With a cache enabled (`--cache-dir`), an unchanged target is never re-scanned —
the "cheap at scale" pillar. Cache entries have a configurable TTL because new
vulnerabilities can affect an unchanged artifact; the key also folds in the scanner tool and
its vulnerability-DB version, so a DB refresh (new CVEs) invalidates stale results before the
TTL expires.

For **container images**, the target identity is the immutable **digest** when known,
falling back to the tag otherwise. A tag is mutable — a rebuilt image pushed under the same
tag would keep the same key and serve the old scan until the TTL. To make caching
content-addressed (a rebuilt image re-scans immediately), give each image a `digest:` in the
Saga: the `k8s-images` surveyor records the running digest automatically, and Draugr scans
the digest-pinned reference so the bytes scanned match what the result is cached under.

## Verdict & exit code

The Norn produces `pass` / `fail`. `draugr scan` exits non-zero on `fail`, so it gates a
pipeline directly. The failure threshold is configurable (`--fail-on`, default `error`),
with optional per-control overrides, plus a component-aware priority gate
(`--fail-on-priority`). The run fails if either gate trips.

## Observability & security posture

Structured logs (`log/slog`), plus OpenTelemetry traces and metrics (opt-in via `OTEL_*`).
Logs and span attributes never carry secrets. Draugr's own CI enforces `govulncheck`,
`gosec`, and `golangci-lint` — it meets the bar it holds others to.
