---
title: Surveyors
description: Discovery plugins that map your app's surface and write the Saga for you.
section: Core concepts
order: 40
---

# Surveyors

**Surveyors** discover your app's surface and return Saga fragments, so the
[descriptor](saga.md) can write itself. Run them with
[`draugr survey`](../reference/cli.md#draugr-survey).

## Why discovery exists

The honest problem with a descriptor is the first one: writing it. A platform team with sixty
services is not going to hand-type sixty components, and a hand-typed list is out of date the
week after it's written — a service is added, an image is retagged, a namespace is split.

Discovery inverts that. The environment already knows what is running; a surveyor reads it and
produces the components, so the descriptor starts complete and stays that way by being re-run.

## Built-in surveyors

| Surveyor | Discovers | Auth |
|---|---|---|
| `k8s-images` | Unique container images running in a cluster or namespace, with their digests | Ambient kubeconfig (`KUBECONFIG`, `~/.kube/config`, or in-cluster) |
| `github-org-repos` | Repositories in a GitHub organization | `GITHUB_TOKEN`, or a token in scope config |

```bash
draugr survey --github-org my-org -o draugr.saga.yaml
draugr survey --k8s-images --k8s-namespace prod --merge -o draugr.saga.yaml
```

At least one surveyor must be selected — `survey` will not guess what you meant to discover.

## Merging, not overwriting

`--merge` folds discovered components into the Saga already at `--output` instead of replacing
it. This is the flag that makes discovery repeatable: the classifications, exclusions and
per-component overrides you added by hand are preserved, and whatever has appeared in the
environment since the last run is added alongside them.

Without it, `survey` writes a fresh descriptor — right for the first run, and a way to lose
hand-written context on every one after that.

## What `k8s-images` records beyond the image

Two things that matter later:

**The running digest.** A tag is mutable; the digest is the bytes actually running. Recording it
makes caching content-addressed — a rebuilt image pushed under the same tag re-scans immediately
instead of serving a stale result until its TTL expires — and it means the finding describes
what is deployed rather than what the tag points at today. See
[content-hash caching](controls-and-scanners.md#content-hash-caching).

**A proposed `exposure`.** When scoped to a specific namespace, `k8s-images` infers each
component's exposure from cluster topology: an Ingress or externally-reachable Service means
`public`, a NetworkPolicy that scopes it means `restricted`, and anything else is `internal`.

## What discovery cannot do for you

A surveyor reads the environment, so it can only recover what the environment knows.

**`criticality` is not in the cluster.** What it costs your business when a component fails is
not a property of any manifest — it is a judgement, and Draugr will not manufacture one.
Discovery leaves it unset; [`draugr classify`](../reference/cli.md#draugr-classify-sagayaml)
asks you. Until both axes are set, [prioritization](prioritization.md) has half its input.

**The proposed `exposure` is a proposal.** Topology is good evidence, not proof — a Service with
no Ingress may still be reachable through a gateway the cluster cannot see. Review it.

The failure discovery protects you from is a component nobody scanned. The one it cannot protect
you from is a component ranked as though it does not matter.

## Going deeper

- [`draugr survey`](../reference/cli.md#draugr-survey) — every flag
- [`draugr classify`](../reference/cli.md#draugr-classify-sagayaml) — set the two risk axes
- [The Saga](saga.md) — what the fragments are merged into
- [Prioritization](prioritization.md) — what `exposure` and `criticality` drive
- [`k8s-images`](../../internal/surveyors/k8s-images.md) ·
  [`github-org-repos`](../../internal/surveyors/github-org-repos.md) — per-surveyor detail
