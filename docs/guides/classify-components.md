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
draugr classify draugr.saga.yaml          # classify unclassified components
draugr classify draugr.saga.yaml --all    # re-classify every component
```

```
Component: web
  Exposure — how reachable is it?
  Reachable from the public internet? [y/N] y
  Does it require authentication? [y/N] n
  Criticality — impact if it fails or is compromised?
    1) outage or data loss   2) degraded, no outage   3) limited impact
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

## By hand, or from discovery

Prefer to hand-edit? Set `exposure` and `criticality` directly on a component — see the
[Saga schema](../reference/saga-schema.md#components). And `draugr survey` on a Kubernetes
namespace already **proposes** each component's `exposure` from topology (Ingress/external
Service → `public`, NetworkPolicy → `restricted`, else `internal`); review it, then fill in
`criticality`. A component left **unclassified** is treated as high-risk, so nothing slips.

Once classified, focus with `--min-priority P2` and gate with `--fail-on-priority P1` (see the
[CLI reference](../reference/cli.md#draugr-scan-sagayaml)).
