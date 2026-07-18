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
ranking: a CVE on CISA **KEV** (Known Exploited Vulnerabilities — confirmed exploited) becomes
critical, and a CVE at/above an **EPSS** (Exploit Prediction Scoring System) threshold is
bumped one band. Supply the data with `--kev`/`--epss` (offline, bring-your-own files).

- **Focus:** `--min-priority P2` lists only the findings worth acting on now
  (P1 = act now · P2 = this cycle · P3 = backlog · P4 = track).
- **Gate:** `--fail-on-priority P1` fails the build on any P1 — component-aware gating with no
  per-component config.
- A component left **unclassified** is treated as high-risk, so nothing slips silently.

Set `exposure` and `criticality` by hand (see the [Saga schema](../reference/saga-schema.md))
or with the guided [`draugr classify`](../reference/cli.md#draugr-classify-sagayaml) wizard.
