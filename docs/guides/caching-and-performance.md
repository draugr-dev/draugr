---
title: Caching & performance
description: Speed up repeat scans with content-hash caching and tune scan parallelism.
section: Guides
order: 50
---

# Caching & performance

Two knobs keep Draugr fast at scale: a **content-hash cache** that skips re-scanning unchanged
targets, and a **parallelism** setting that matches the run to the machine.

## Content-hash caching

Each scan job has a cache key derived from its inputs (scanner, version, target identity,
config). Enable a cache and an unchanged target is never re-scanned:

```bash
draugr scan draugr.saga.yaml --cache-dir .draugr-cache
draugr scan draugr.saga.yaml --cache-dir .draugr-cache --cache-ttl 12h
```

| Flag | Default | Description |
|------|---------|-------------|
| `--cache-dir` | — | Enable content-hash caching in this directory |
| `--cache-ttl` | `24h` | Cache entry lifetime (`0` = no expiry) |

**Every scanner folds its own version into the key** — and, where the answer depends on data the
tool downloads rather than on the tool itself, that data's version:

| Scanner | What the key follows |
|---|---|
| `trivy`, `trivy-fs`, `trivy-config`, `trivy-license` | Trivy's version **and its vulnerability-database timestamp** |
| `nuclei` | the **template set** version — republished daily, so this is the one that moves |
| `semgrep`, `gitleaks`, `gosec`, `kube-bench` | the tool's version |
| `kube-bench-job` | the pinned image digest |
| `http-headers`, `tls-probe`, `k8s-policies` | Draugr's own version — their rules ship in the binary |

So the thing that would change the answer changes the key, and a cached result is invalidated by
the update that made it wrong rather than by waiting out the clock. A new Nuclei template set, a
Trivy database refresh, a Semgrep upgrade, or a Draugr release that adds a check will each
re-scan what they affect.

Entries still expire on a TTL, as a backstop for what a version cannot express — most notably a
Semgrep ruleset fetched from the registry, whose contents can change without the tool's version
moving. For **container images**, pin a `digest:` in the Saga
so caching is content-addressed — a rebuilt image re-scans immediately instead of serving the
old result under a mutable tag. See [caching in depth](../concepts/controls-and-scanners.md#content-hash-caching).

> **Images without a pinned digest.** If a component's `images:` entry gives only a mutable tag
> (e.g. `python:3.8-slim`) with no `digest:`, the cache keys on that **tag**. An image rebuilt
> and re-pushed under the same tag produces the **same key**, so the cached result is reused
> until it goes stale — either the `--cache-ttl` expires (default `24h`) or you force a re-scan
> (delete the cache entry, or run once without `--cache-dir`). Draugr does **not** reach out to
> the registry to resolve a tag to its current digest. To make a rebuild invalidate the cache
> immediately, pin the immutable `digest:` in the Saga — a discovery surveyor records the running
> digest for you — so the key becomes content-addressed.

## Tuning parallelism

By default Draugr runs up to one scan job per CPU. But scanners like Trivy and Semgrep are
themselves multi-threaded, so on a busy or small machine that default can oversubscribe the box
and *slow the run down* — dial it down with `-j`. On a big CI runner you can dial it up.

```bash
draugr scan draugr.saga.yaml -j 4      # cap parallelism
draugr scan draugr.saga.yaml -j 1      # serial: deterministic output, handy for debugging
```

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --jobs` | `0` (auto) | Max scan jobs to run in parallel (`0` = one per CPU) |

The run's JSON `stats` reports the effective `concurrency` alongside `jobs` (total jobs),
`scans`, `cacheHits`, and `deduped`, so you can see the effect and tune from evidence. See the
[CLI reference](../reference/cli.md#draugr-scan-sagayaml) for the full flag list.
