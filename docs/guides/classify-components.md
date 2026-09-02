---
title: Classify components
description: Set exposure and criticality so Draugr can rank findings by priority.
section: Guides
order: 60
---

# Classify components

Prioritization needs two attributes on each component: **`exposure`** (how reachable it is) and
**`criticality`** (the business impact if it fails). Together they turn a wall of findings into
a ranked P1–P4 list — see [prioritization](../concepts/prioritization.md) for how the bands are
computed.

## The guided wizard

The fastest way to set them is `draugr classify` — it asks a few questions per component and
writes the labels back into your Saga, preserving comments and formatting. By default it only
asks about unclassified components:

```bash
draugr classify                             # the descriptor in this directory
draugr classify --all                       # re-classify every component
draugr classify --components web,api        # only these two, classified or not
```

It finds the descriptor the way `draugr scan` does, so the path is only needed when you have
more than one or it is somewhere else. `--components` is what to reach for when one classification
turned out wrong: naming a component re-asks about it without disturbing the others.

```
Component: web
  Exposure — who can reach it?
    1) public         anyone on the internet can reach it, no sign-in
    2) authenticated  on the internet, but behind a login
    3) internal       only from inside your own network or VPN
    4) restricted     inside your network and locked down further — an allowlist, a private link, its own segment
  Choose [1-4]: 1
  Criticality — what happens if it fails or is breached?
    1) critical       an outage or data loss for the business
    2) important      degraded service, but no outage
    3) supporting     limited impact, easily worked around
  Choose [1-3]: 1
  → web: exposure=public, criticality=critical
```

## The ladders

Both are fixed ladders (an organization can redefine the meaning; the levels stay stable):

| `exposure` | meaning | | `criticality` | meaning |
|------------|---------|-|---------------|---------|
| `public` | internet-facing, no auth | | `critical` | failure causes outage / data loss |
| `authenticated` | internet-facing, behind auth | | `important` | degraded, no immediate outage |
| `internal` | reachable within the environment | | `supporting` | limited operational impact |
| `restricted` | namespace- / network-policy-scoped | | | |

**`criticality: critical` is not `severity: critical`.** This ladder describes the *component* —
how much the organization depends on it. Severity describes a *flaw*, and a scanner assigns it: how
much harm it could cause if it were exploited. A component you mark `critical` will still carry
low-severity findings, and both words appear on the same finding. See
[prioritization](../concepts/prioritization.md) for the tables where the two meet.

## By hand, or from discovery

Prefer to hand-edit? Set `exposure` and `criticality` directly on a component — see the
[Saga schema](../reference/saga-schema.md#components). And `draugr survey` on a Kubernetes
namespace already **proposes** each component's `exposure` from topology (Ingress/external
Service → `public`, NetworkPolicy → `restricted`, else `internal`); review it, then fill in
`criticality`. A component left **unclassified** is treated as high-risk, so nothing slips.

Once classified, focus with `--min-priority P2` and gate with `--fail-on-priority P1` (see the
[CLI reference](../reference/cli.md#draugr-scan-sagayaml--dir)).
