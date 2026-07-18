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

Entries expire on a TTL because new vulnerabilities can affect an unchanged artifact; the key
also folds in the scanner tool and its vulnerability-DB version, so a DB refresh (new CVEs)
invalidates stale results before the TTL. For **container images**, pin a `digest:` in the Saga
so caching is content-addressed — a rebuilt image re-scans immediately instead of serving the
old result under a mutable tag. See [caching in depth](../concepts/controls-and-scanners.md#content-hash-caching).

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
