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
| `draugr-headers`, `draugr-tls`, `draugr-k8s-policies` | Draugr's own version — their rules ship in the binary |

So the thing that would change the answer changes the key, and a cached result is invalidated by
the update that made it wrong rather than by waiting out the clock. A new Nuclei template set, a
Trivy database refresh, a Semgrep upgrade, or a Draugr release that adds a check will each
re-scan what they affect.

**Entries are compressed.** A cached entry is a whole SARIF report, which is repetitive by
construction — a measured one went from 375 KB to 60 KB. That matters most where the cache is
persisted between CI runs, because an uncompressed cache spends on restore what it saves on
scanning. A cache written by an older Draugr is read as-is, so upgrading does not throw one away.

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

## Persisting the cache between CI runs

A runner is fresh every time, so a pipeline pays full price for scanning artifacts that have not
changed since the last run. Two different things are worth persisting, and they are not equally
risky.

### Cache the scanner's data first

This is the bigger win and it carries no trust question at all. Trivy's databases are **2.6 GB**
— 1.4 GB of Java index and 1.2 GB of vulnerability data — and a cold runner downloads all of it
before scanning anything. For many projects that is larger than the scanning.

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/trivy
    key: trivy-db-${{ github.run_id }}
    restore-keys: trivy-db-
- uses: draugr-dev/draugr@v0
  with: { saga: draugr.saga.yaml, tools: true }
```

A stale copy here cannot fabricate a result. The worst it does is make a scan fail, or report data
Draugr already folds into the cache key — so nothing downstream is deceived.

Nuclei's template set (`~/.local/nuclei-templates` by default) is worth the same treatment if you
run `dast`.

### Then, if it earns its place, the result cache

`--cache-dir` stores scan *results*, so a persisted copy skips whole jobs rather than re-fetching
data. It is the smaller saving and it introduces a real question, because **an entry is a pass**:

```yaml
- uses: actions/cache@v4
  with:
    path: .draugr-cache
    key: draugr-${{ github.sha }}
    restore-keys: draugr-
- uses: draugr-dev/draugr@v0
  with: { saga: draugr.saga.yaml, cache-dir: .draugr-cache }
```

**Anyone who can write the cache can make a scan report a pass it never earned.** That is an
attack on the gate itself, and it is worth being plain about what does and does not protect you:

- **`actions/cache` scopes writes by branch**, so a pull request from a fork cannot write the
  default branch's cache. The first-party action also passes `--cache-read-only` automatically on
  a fork pull request, so the guarantee does not depend on which transport you chose.
- **A shared volume, a bucket or a self-hosted runner has no such scoping.** If untrusted code can
  write there, pass `--cache-read-only` yourself on those jobs.
- **Nothing here is signed.** Draugr does not verify who wrote an entry. If that matters for your
  threat model, do not share a cache across trust boundaries.

### What a hit does and does not promise

The key covers the scanner, its data version, the target's identity and the effective config, so
a Trivy database refresh or a Nuclei template update invalidates what it affects. Two things it
cannot cover:

- **A container image named only by a tag.** Rebuild and re-push `acme/api:latest` and the key is
  unchanged, so the previous image's findings are served. Pin a `digest:` — a discovery surveyor
  records the running one for you — or pass `--cache-require-digest` to refuse to cache tag-only
  images at all.
- **A Semgrep ruleset fetched from the registry.** `p/default` is a moving target with no version
  Draugr can read, and resolving it means fetching it, which costs most of what caching saves.
  This is the case `--cache-ttl` exists for; leave it at a day or less if you rely on registry
  rulesets.

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
