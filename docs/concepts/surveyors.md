---
title: Surveyors
description: Discovery plugins that map your app's surface and write the Saga for you.
section: Core concepts
order: 40
---

# Surveyors

**Surveyors** discover your app's surface and return Saga fragments, so the descriptor can
write itself. Built-in: **`k8s-images`** (unique images in a cluster/namespace) and
**`github-org-repos`** (repositories in a GitHub org).

Run them with [`draugr survey`](../reference/cli.md#draugr-survey) and materialize the results
into a Saga. When scoped to a namespace, `k8s-images` also **proposes each component's
`exposure`** from topology — review it, then set `criticality` with
[`draugr classify`](../reference/cli.md#draugr-classify-sagayaml). See
[prioritization](prioritization.md) for how those two axes drive what to fix first.
