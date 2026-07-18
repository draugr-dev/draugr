---
title: Surveyors — the Ravens
description: Discovery plugins that map your app's surface and write the Saga for you.
section: Core concepts
order: 40
---

# Surveyors — "the Ravens"

**Surveyors** discover your app's surface and return Saga fragments, so the descriptor can
write itself. Built-in: **`k8s-images`** (unique images in a cluster/namespace) and
**`github-org-repos`** (repositories in a GitHub org). Named for Odin's ravens, Huginn and
Muninn, who fly the world and report back.

Run them with [`draugr survey`](../reference/cli.md#draugr-survey) and materialize the results
into a Saga. When scoped to a namespace, `k8s-images` also **proposes each component's
`exposure`** from topology — review it, then set `criticality` with
[`draugr classify`](../reference/cli.md#draugr-classify-sagayaml). See
[prioritization](prioritization.md) for how those two axes drive what to fix first.
