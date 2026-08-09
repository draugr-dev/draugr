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

| Command | Discovers | Auth |
|---|---|---|
| `draugr survey k8s images` | Unique container images running in a cluster or namespace, with their digests | Ambient kubeconfig (`KUBECONFIG`, `~/.kube/config`, or in-cluster) |
| `draugr survey k8s cluster` | The cluster itself, as an `infrastructure` component to audit | Ambient kubeconfig |
| `draugr survey github repos` | Repositories in a GitHub organization | `GITHUB_TOKEN`, or a token in scope config |

Each surveyor is a subcommand, so its options live with it — `--namespace` belongs to
`k8s images` and cannot be handed to `github repos` to be quietly ignored.

```bash
draugr survey github repos --org my-org -o draugr.saga.yaml
draugr survey k8s images --namespace prod -o draugr.saga.yaml
draugr survey k8s cluster --context prod -o draugr.saga.yaml

# Several namespaces, one component each
draugr survey k8s images --namespace payments --namespace checkout -o draugr.saga.yaml
```

**A namespace is a component.** `--namespace` repeats, and each one is surveyed on its own terms:
its component is named after it, and its exposure is proposed from its own topology. Naming none
discovers the whole cluster as a single component with no exposure proposed, because one exposure
covering everything running anywhere in a cluster would not mean anything.

`k8s images` and `k8s cluster` read the same cluster but describe different things, and are
deliberately separate: the images are the application, the cluster is what it runs on, and they
will differ in criticality. A surveyor named for images that also emitted an infrastructure
component would surprise anyone reading the command that produced the descriptor.

`--context` selects which cluster, for both.

`draugr survey` on its own lists the surveyors rather than guessing what you meant to discover.

## Merging, not overwriting

A survey folds discovered components into the Saga already at `--output` instead of replacing
it, and that is the default rather than a flag. It is what makes discovery repeatable: the
classifications, exclusions and
per-component overrides you added by hand are preserved, and whatever has appeared in the
environment since the last run is added alongside them. Pass `--replace` when you do want to
start again.

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
Discovery leaves it unset; [`draugr classify`](../reference/cli.md#draugr-classify-sagayaml--directory)
asks you. Until both axes are set, [prioritization](prioritization.md) has half its input.

**The proposed `exposure` is a proposal.** Topology is good evidence, not proof — a Service with
no Ingress may still be reachable through a gateway the cluster cannot see. Review it.

The failure discovery protects you from is a component nobody scanned. The one it cannot protect
you from is a component ranked as though it does not matter.

## Going deeper

- [`draugr survey`](../reference/cli.md#draugr-survey) — every flag
- [`draugr classify`](../reference/cli.md#draugr-classify-sagayaml--directory) — set the two risk axes
- [The Saga](saga.md) — what the fragments are merged into
- [Prioritization](prioritization.md) — what `exposure` and `criticality` drive
- [`k8s-images`](../../internal/surveyors/k8s-images.md) ·
  [`github-org-repos`](../../internal/surveyors/github-org-repos.md) — per-surveyor detail
