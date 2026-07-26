---
title: Prioritization
description: How exposure, criticality, and severity combine into a P1–P4 priority band.
section: Core concepts
order: 30
---

# Prioritization: what to fix first

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
ranking — see [Exploitability: KEV and EPSS](#exploitability-kev-and-epss) below.

- **Focus:** `--min-priority P2` lists only the findings worth acting on now
  (P1 = act now · P2 = this cycle · P3 = backlog · P4 = track).
- **Gate:** `--fail-on-priority P1` fails the build on any P1 — component-aware gating with no
  per-component config.
- A component left **unclassified** is treated as high-risk, so nothing slips silently.

Set `exposure` and `criticality` by hand (see the [Saga schema](../reference/saga-schema.md))
or with the guided [`draugr classify`](../reference/cli.md#draugr-classify-sagayaml) wizard.

## Exploitability: KEV and EPSS

CVSS says how bad a vulnerability *could* be in the abstract. It says nothing about whether
anyone is actually exploiting it. Two public datasets close that gap, and Draugr folds either
into a finding's severity **before** it is ranked — so "what to fix first" reflects the real
world, not just the theory. New to these? [EPSS & KEV explained](/learn/epss-and-kev/) covers
the concepts; this page covers using them.

| Signal | What it is | Effect on a matching finding |
|--------|------------|------------------------------|
| **KEV** | CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog — CVEs with *confirmed, observed* exploitation | severity becomes **critical**, whatever it was |
| **EPSS** | FIRST's [Exploit Prediction Scoring System](https://www.first.org/epss/) — a daily 0–1 probability that a CVE will be exploited in the next 30 days | severity is raised **one band** (low→medium→high→critical) when the score is at or above `--epss-threshold` |

KEV wins where both apply: observed exploitation outranks a prediction about it.

### Using them

Both are **offline, bring-your-own**: you download the feed, Draugr reads the file. It never
calls CISA or FIRST during a scan — no network dependency in your pipeline, nothing leaves your
environment about what you're scanning, and the same inputs produce the same verdict.

```bash
# fetch the feeds (daily is plenty — KEV changes rarely, EPSS is republished each day)
curl -fsSL -o kev.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl -fsSL https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | gunzip > epss.csv

draugr scan draugr.saga.yaml --kev kev.json --epss epss.csv
draugr scan draugr.saga.yaml --epss epss.csv --epss-threshold 0.1   # widen the net
```

`--kev` takes CISA's JSON as published; `--epss` takes FIRST's CSV (`cve,epss,percentile` —
comment and header lines are skipped). Either flag works on its own.

### Choosing an EPSS threshold

`--epss-threshold` defaults to **0.5**: a coin-flip chance of exploitation within 30 days. That
is a deliberately high bar. EPSS scores are heavily skewed — most CVEs sit far below 0.01 — so
lowering the threshold widens the net faster than the number suggests.

| Threshold | Roughly means | Use when |
|-----------|---------------|----------|
| `0.5` (default) | very likely to be exploited | you want few, high-confidence escalations |
| `0.1` | notably elevated risk | a balanced setting for most teams |
| `0.01` | above the long tail | you would rather over- than under-react |

Pick one deliberately and keep it stable: a threshold that moves between runs makes two scans
incomparable.

### What it touches, and what it doesn't

- **Only CVE-identified findings.** Enrichment looks for a CVE id in the finding's rule id, so
  it reaches `sca` and `images` results. SAST, secrets and IaC findings carry no CVE and are
  never escalated — their severities come from the scanner and any control floor.
- **Severity, not priority, directly.** Enrichment raises severity; priority is then recomputed
  from severity × exposure × criticality. An escalated CVE on a `restricted`, `supporting`
  component may still not be P1 — which is the point: exploitability matters *in context*.
- **The gate follows automatically.** Because both bands and levels derive from severity,
  `--fail-on-priority` and `--fail-on` see the enriched values with no extra configuration.

### A worked example

A dependency carries a CVE scored CVSS 6.1 → **medium**, on a component classified `public` /
`important`.

| Run | Severity | Priority |
|-----|----------|----------|
| no enrichment | medium | P3 |
| `--epss epss.csv`, score 0.62 ≥ 0.5 | high (one band up) | P2 |
| `--kev kev.json`, and it's listed | critical | P1 |

Same finding, same component, three different answers about when to fix it — and the last is the
one that matters, because somebody is exploiting it today.

**Related:** [EPSS & KEV explained](/learn/epss-and-kev/) ·
[Vulnerability prioritization](/learn/vulnerability-prioritization/) ·
[CVE, CVSS and severity](/learn/cve-cvss-and-severity/) ·
[`scan` flags](../reference/cli.md#draugr-scan-sagayaml--dir)
