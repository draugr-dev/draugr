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
draugr scan draugr.saga.yaml --cache-dir .draugr/cache
draugr scan draugr.saga.yaml --cache-dir .draugr/cache --cache-ttl 12h
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
the update that made it wrong rather than by waiting out the clock. [The cache
architecture](../contributing/cache.md) explains how the key is built and why identity has to mean
content. A new Nuclei template set, a
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

## Configure it once, per machine

The `--cache-*` flags all have a home in [`draugr.config.yaml`](../reference/cli.md#draugr-config),
which is usually the better place for them: a cache directory describes a runner image, not an
application, and every pipeline on that runner wants the same one.

```yaml
# draugr.config.yaml
cache:
  dir: /var/cache/draugr
  ttl: 24h
  requireDigest: true     # do not cache an image named only by a tag
```

A flag you type always wins. `readOnly` and `requireDigest` only ever turn *on* from the config —
a project file that does not discuss caching should not undo a machine that declared its results
untrustworthy — but typing `--cache-read-only=false` still overrides it, because you typed it.

## Persisting the cache between CI runs

A runner is fresh every time, so a pipeline pays full price for scanning artifacts that have not
changed since the last run. Two different things are worth persisting, and they are not equally
risky.

### Cache the scanner's data first

This is the bigger win and it carries no trust question at all. Trivy's databases are up to
**2.6 GB** — 1.2 GB of vulnerability data, plus 1.4 GB of Java index *if you scan Java artifacts*,
which Trivy fetches only when something needs it. A cold runner downloads all of what it needs
before scanning anything, and for many projects that is larger than the scanning.

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

### Or run one Trivy server for the whole fleet

If you have enough runners that persisting a database on each is its own problem,
[Trivy's client/server mode](https://trivy.dev/docs/latest/references/modes/client-server/) holds
the databases once and serves them. Draugr needs no configuration for this — it passes its
environment to the tools it runs, so the variable Trivy already understands is enough:

```yaml
env:
  TRIVY_SERVER: http://trivy.internal:8080
  # TRIVY_TOKEN: ...   if the server was started with --token
```

Measured against a server with an **empty** local cache: the `sca` control returned its usual
findings and downloaded nothing — no 1.2 GB, no cache directory created at all.

**It does not cover everything, and the gap is easy to miss.** Trivy's client/server mode supports
image, filesystem and repository scanning, and deliberately does *not* support `trivy config` —
so the `iac` control still runs locally and still wants its policy bundle. Misconfiguration and
secret scanning stay client-side by design, so that files which may hold sensitive data are never
sent to the server. And Draugr runs more than Trivy: Gitleaks, Semgrep and Nuclei keep their own
data regardless.

So a server is worth it when a platform team already runs services and the fleet is large enough
to care. One or a few runners are better served by the directory cache above, which needs nobody
to operate it.

### Then, if it earns its place, the result cache

`--cache-dir` stores scan *results*, so a persisted copy skips whole jobs rather than re-fetching
data. It is the smaller saving and it introduces a real question, because **an entry is a pass**:

```yaml
- uses: actions/cache@v4
  with:
    path: .draugr/cache
    key: draugr-${{ github.sha }}
    restore-keys: draugr-
- uses: draugr-dev/draugr@v0
  with: { saga: draugr.saga.yaml, cache-dir: .draugr/cache }
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

  **The report says when this happened**, so it is a caveat you are given rather than one you have
  to remember:

  ```
  Reused from cache, keyed on a tag: acme/api:latest — a tag can be rebuilt, so these findings
  may describe an earlier image. Pin a digest, or re-scan with --cache-require-digest.
  ```

  It appears only when a result was actually reused: a fresh scan of a tag scanned whatever that
  tag points at now, which is the right answer whether or not it moved. `--format json` carries
  the same list as `stats.unpinnedCacheHits`.

  Draugr does not resolve the digest for you. That is a registry request and a credential the run
  may not have, and a scan that fails because it could not reach a registry it never needed to
  reach would be a worse trade than the caveat.
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
[CLI reference](../reference/cli.md#draugr-scan-sagayaml--dir) for the full flag list.

## Finding out where a slow run went

A job count says how much was planned, not what it cost. `stats` also carries the timings, in
milliseconds:

```bash
draugr scan draugr.saga.yaml -o out
jq '.stats' out/report.json
```

```json
{
  "jobs": 6,
  "scans": 6,
  "cacheHits": 0,
  "deduped": 0,
  "concurrency": 32,
  "durationMs": 4400,
  "byControlMs": {
    "iac": 1816,
    "licenses": 1797,
    "sast": 6876,
    "sca": 1736,
    "secrets": 1257
  }
}
```

Read it in this order:

1. **`durationMs` is what you waited; `byControlMs` is not.** The per-control figures are job
   time summed across each control's jobs, so with any parallelism they add up to more than the
   wall-clock — 13.5 seconds of work in 4.4 seconds elapsed, above. That is the concurrency
   working, not a bug. Compare controls against each other, never against `durationMs`.
2. **The largest entry is the one worth attention**, whatever the job count says: one slow job
   costs more than four fast ones. Here it is `sast`, at more than the other four together —
   so tuning anything else would buy nothing.
3. **`toolWaitsMs` separates a slow tool from a contended one.** Several controls can share a
   single tool and its cache — `iac`, `licenses` and `sca` are all Trivy above — and only one
   may use it at a time. Time recorded there was spent queueing rather than scanning, so raising
   `-j` will not recover it. The key is absent in this run because Draugr warms shared scanner
   state once before the fan-out; if you see it, the warm-up did not cover that tool, and the
   fix is a warm cache rather than more parallelism.
4. **`cacheHits: 0` with a `--cache-dir` set** means the cache was there and nothing matched.
   Entries are keyed on content, and for a repository that includes the revision, so a run on a
   new commit is *expected* to miss. A content cache is worth what it saves when the same input
   is scanned again — a re-run, a retry, a second component sharing a repository — not on the
   next commit.

The timings are absent rather than zero when a run recorded none, so a consumer charting them
can tell "not measured" from "took no time".

## Scanners that call a rate-limited API

**You do not need to slow the whole run down for one of them.** A scanner that talks to a hosted
API declares how often it may be called, and Draugr spaces *its* calls out — while everything else
keeps running at full parallelism.

`virustotal` is the example: its public tier allows four requests a minute, so Draugr leaves
fifteen seconds between its lookups. A scan of three hosts takes about thirty seconds, no request
is ever rejected, and no other control waits for it.

The waiting happens **before** a worker is taken, which is what makes that true. Were the scanner
to hold a slot while waiting, a handful of its jobs would occupy the pool and every unrelated
control would queue behind a scanner it has nothing to do with. Lowering `-j` would be the wrong
fix for the same reason: it trades a global slowdown for one scanner's local limit.

If your key allows more, say so — per scanner, not globally:

```yaml
config:
  controllers:
    threats:
      virustotal:
        requestsPerMinute: 1000    # a paid key; the default assumes the free tier's 4
```

Raise it only to what your key actually permits. Exceeding a vendor's published limit risks losing
access, and some state a permanent ban as the penalty for terms violations.
