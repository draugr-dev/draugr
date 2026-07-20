---
title: The Saga
description: The draugr.saga.yaml descriptor — a security bill of materials for a running app.
section: Core concepts
order: 10
---

# The Saga (descriptor)

Draugr turns a description of your app into trustworthy, audit-ready security evidence. The
starting point is the **Saga**.

`draugr.saga.yaml` is the source of truth — a *security bill of materials for a running
application*. It lists your **components** (repositories, images, hosts, infrastructure)
and which **controls** must pass. You write what you know; Draugr does the rest. See the
[Saga schema](../reference/saga-schema.md).

From the Saga, Draugr resolves which [controls and scanners](controls-and-scanners.md) apply,
ranks findings by [priority](prioritization.md), and produces a
[verdict](verdict-and-gating.md). If you'd rather not hand-write the descriptor, the
[Ravens](surveyors.md) can discover your surface and write it for you.
