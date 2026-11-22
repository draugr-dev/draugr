---
title: Rank findings by priority
description: Set exposure and criticality so Draugr can rank findings by priority.
section: Guides
order: 60
---

# Classify components

Prioritization needs two attributes on each component: **`exposure`** (how reachable it is) and
**`criticality`** (the business impact if it fails). Together they turn a wall of findings into a
ranked P1–P4 list. See [prioritization](../concepts/prioritization.md) for how the bands are
computed.

## The guided wizard

The fastest way to set them is `draugr classify`. It asks a few questions per component and writes
the labels back into your Saga, preserving comments and formatting. By default it only asks about
unclassified components:

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
  Exposure, who can reach it?
    1) public         anyone on the internet can reach it, no sign-in
    2) authenticated  on the internet, but behind a login
    3) internal       only from inside your own network or VPN
    4) restricted     inside your network and locked down further, an allowlist, a private link, its own segment
  Choose [1-4]: 1
  Criticality, what happens if it fails or is breached?
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
| `public` | anyone on the internet, no sign-in | | `critical` | an outage or data loss for the business |
| `authenticated` | on the internet, behind a login | | `important` | degraded service, but no outage |
| `internal` | only from inside your network or VPN | | `supporting` | limited impact, easily worked around |
| `restricted` | inside your network and locked down further, an allowlist, a private link, its own segment | | | |

**`criticality: critical` is not `severity: critical`.** This ladder describes the *component*, the
business impact if it fails. Severity describes a *flaw*, and a scanner assigns it: how
much harm it could cause if it were exploited. A component you mark `critical` will still carry
low-severity findings, and both words appear on the same finding. See
[prioritization](../concepts/prioritization.md) for the tables where the two meet.

## Libraries

A library has no deployment of its own, so its `exposure` and `criticality` come from where it is
used. Left undeclared, a library is ranked as `public` and `critical` like any other component,
which is the cautious answer for one nobody has looked at.

- A library used inside public services keeps `exposure: public`, because a flaw in it is reachable
  the way a flaw in those services is.
- A library only a build tool uses can declare `exposure: internal`, on its owner's say-so, written
  in the descriptor where review sees it.

Pick `criticality` the same way, from the most critical component that uses the library.

```yaml
components:
  - name: pricing             # a library the public checkout service imports
    exposure: public
    criticality: critical
    repositories:
      - url: https://github.com/acme/pricing.git
  - name: changelog-parser    # a library only the release tooling uses
    exposure: internal        # its owner's call, seen in review
    criticality: important
    repositories:
      - url: https://github.com/acme/changelog-parser.git
```

Declaring a lower `exposure` or `criticality` moves the library's findings down, so a high-severity
flaw that ranks P1 in `pricing` ranks P3 in `changelog-parser`. That is why the lower level is a
reviewed declaration in the descriptor rather than a default.

## By hand, or from discovery

Prefer to hand-edit? Set `exposure` and `criticality` directly on a component. See the [Saga
schema](../reference/saga-schema.md#components). And `draugr survey` on a Kubernetes namespace
already **proposes** each component's `exposure` from topology (Ingress/external Service →
`public`, NetworkPolicy → `restricted`, else `internal`); review it, then fill in `criticality`. A
component left **unclassified** is treated as high-risk, so nothing slips.

Once classified, focus with `--min-priority P2`; the gate is already `--fail-on P1` (see the
[CLI reference](../reference/cli.md#draugr-scan-sagayaml--dir)).
