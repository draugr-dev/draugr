# The cache architecture

How Draugr avoids repeating work, and — more importantly — the rules that keep it from serving an
answer that is no longer true.

This is the explanation. For turning caching on and persisting it between CI runs, see
[caching & performance](../guides/caching-and-performance.md).

## Three caches, not one

They are separate, owned by different parties, and confusing them is the usual source of “why did
that re-run”.

| | What it holds | Who owns it | Lifetime |
|---|---|---|---|
| **Result cache** | a finished SARIF report for one scan job | Draugr | opt-in, TTL-bounded |
| **Tool data** | a scanner's own database — Trivy's vulnerability DB, Nuclei's templates, retire.js's advisories | the tool | until the tool refreshes it |
| **In-run state** | version probes, and whatever a scanner warms before the fan-out | Draugr, per run | the process |

Only the first is Draugr's cache in the usual sense. The second is the one that dominates a cold
CI job — a scanner downloading its database costs far more than re-running the scan — which is why
the CI guidance persists tool data *first* and treats the result cache as a later optimisation.

## The result cache

### The key

`plugin.ComputeCacheKey` (`pkg/plugin/config.go`) hashes the inputs that can change the answer:

```
sha256( scanner ∥ version ∥ target-kind ∥ target-identity ∥ sorted(config k=v) )
```

Hex-encoded, so it is also safe as a filename. Config keys are sorted because map iteration is not
ordered, and an unstable key is a cache that never hits.

**`version` is not always the scanner's own.** A scanner may implement `plugin.CacheVersioner` to
contribute the version of whatever actually decides its answer — Trivy's vulnerability database
timestamp, Nuclei's template set. This matters because the tool can be unchanged while its data is
not, and it is the data that found the finding. The engine resolves it lazily and only when caching
is on, since it costs a subprocess; an empty answer falls back to `Info().Version`.

The effect is that an entry is invalidated by *the update that made it wrong*, rather than by
waiting out a clock.

### Target identity

Each target kind decides what identity means, in `pkg/plugin/target.go`. The details are where the
correctness lives:

- **Repository** — `source@revision`, plus `+worktree` when scanning an uncommitted tree, plus a
  scope marker when `paths`/`ignore` narrow it. Credentials are deliberately **excluded**: they are
  how a repository is fetched, not which repository it is, so including them would give two people
  scanning one repository different identities.
- **Image** — the digest when there is one, otherwise the reference.
- **Host** — the normalised URL, plus markers for the authentication and the spec in use. Two scans
  of one URL that are not comparable — one authenticated, one not — must not share a key.
- **Infrastructure** — the platform and the named instance.

### Why identity has to mean content

A cache is only sound if *the same identity implies the same bytes*. A commit and a digest are
content addresses; a mutable tag is not — `app:latest` can be rebuilt under the same name, and a
key built from it would serve findings for an image that no longer exists.

`plugin.ContentAddressable` lets a target declare this, and the default for a kind that does not
implement it is *content-addressed*, because a repository at a revision and a host at a URL both
are.

Two things follow, and the first is the interesting one:

- **A hit on a mutable identity is reported.** When a cached result is reused for a target whose
  identity is not its content — a tag-named image — the run records it and the console says so
  (`Stats.UnpinnedCacheHits`, surfaced in the report and in the JSON). The assumption is recorded
  per *hit* rather than per job, because a target only rests on it when its result was actually
  reused: a fresh scan of a tag scanned whatever the tag points at now, which is the right answer
  whether or not it moved. Reusing a stale result silently would be a passing verdict resting on
  an assumption nobody stated.
- **`--cache-require-digest`** (or `cache.requireDigest`) goes further and makes a tag-named image
  **not cacheable at all**, via the engine's `WithCacheableTarget` predicate, rather than caching
  it and hoping.

`--working-tree` refuses to cache for the same class of reason: a working tree's content changes
between two runs at the same revision, so a cache keyed on the revision would serve the previous
edit's findings — the exact opposite of what somebody iterating on a fix needs.

### The implementations

`pkg/cache/cache.go`, all behind one `Cache` interface:

- **`Noop`** — stores nothing, always misses. The default, because a cache is a promise that an
  unchanged input has an unchanged answer, and that is a promise somebody should opt into.
- **`Memory`** — process-lifetime, no TTL. Two jobs in one run that resolve to the same key.
- **`Local`** — a directory, with TTL expiry. What `--cache-dir` gives you.
- **`ReadOnly(c)`** — serves entries, stores none.

`ReadOnly` is a **wrapper rather than a flag** on purpose: the guarantee is structural, and a
boolean checked inside `Put` is a boolean somebody can forget to check. It exists for a run whose
results the next run should not trust — a pull request from a fork being the case that matters,
where the code deciding what the scan sees is not the code the cache is meant to describe. Reading
stays useful, because the entries already there were written by runs that were trusted.

Writing is discarded silently there, deliberately: a read-only cache is a configuration, not an
error, and a scan that failed because it could not write a cache would be absurd.

### What is on disk

One file per key, in the cache directory:

```
<cache-dir>/<hex-sha256-of-the-key>.json.gz   0600, in a directory created 0750
```

The contents are **gzipped JSON** of a small envelope — the report, and when it was stored:

```json
{"report": { … the whole SARIF report … }, "storedAt": "2026-08-15T20:28:34Z"}
```

Three details that are easy to get wrong when working on this:

- **The name describes the bytes.** A cached entry is a whole SARIF report and therefore
  repetitive by construction — one measured entry went from 375 KB to 60 KB, which is the
  difference between a cache that is cheap to restore in CI and one that costs more than the scan
  it saves. Entries were called `.json` before they were compressed and kept that name for a
  while afterwards; they are `.json.gz` now, and an entry under the old name is not read. Writing
  the same key removes it, because nothing else would: expiry only makes a read miss, and the
  cache evicts nothing on its own.
- **The TTL is enforced on read, from `storedAt`** — not from the file's mtime, which a restore
  step or a copy would rewrite. An entry restored from a CI cache is as old as the scan that
  produced it, not as old as the restore.
- **Every failure is a miss, not an error.** Absent file, unreadable bytes, malformed JSON,
  expired entry — all return `ok=false` and the job runs normally. A cache is an optimisation, and
  a scan that failed because its cache was corrupt would be a worse outcome than the scan it
  avoided. This is the one place in Draugr where swallowing an error is right, because the
  fallback is doing the work properly rather than reporting a pass.

There is no index and no manifest: a key is a filename, so two processes writing different keys
never contend. Within a process a mutex serialises access; across processes nothing does, and it
does not need to — a write to the same key carries an equivalent report, and the one way that can
go wrong is a reader seeing a half-written file, which is a malformed read, which is a miss. The
fail-soft rule above is what makes the absence of cross-process locking safe rather than lucky.

### Where the settings live

Cache settings are machine configuration (`pkg/config`), **not** descriptor fields — a cache
directory is a fact about a runner image, not about the application being described. Two projects
on one runner want the same cache; one project on two runners does not want its descriptor naming
a path that exists on only one of them.

`dir`, `ttl`, `readOnly`, `requireDigest`, each with a `--cache-*` flag that overrides it.

Note that `ttl: 0` in a config file means *the built-in default*, not “never expire” — a file that
omits a field is not asking for entries that live forever. Setting `0s` explicitly is how you ask.

## Tool data, and contention over it

Scanners keep their own state under `~/.draugr/data/<tool>`, namespaced so one tool's files cannot
collide with another's. Draugr points tools there rather than leaving them in `/tmp` so the data
survives a CI job and can be copied to an air-gapped machine along with everything else.

Two consequences worth knowing when working on a scanner:

- **Prewarm.** `plugin.Prewarmer` warms shared, expensive state **once** before the run fans out.
  Without it, every job in the fan-out discovers the missing database simultaneously and downloads
  it in parallel.
- **Locks are real.** Trivy keeps analysis results in a BoltDB and takes an exclusive write lock.
  Draugr plans one job per image and per repository and runs them concurrently, so two processes
  can want that lock for longer than Trivy will wait, and the loser fails its whole scan. Waiting
  is the right response — the condition clears the moment the holder finishes — but it is never
  done silently: a scan that took three times as long for a reason nobody can see is the same
  problem in a quieter form, so each wait is logged.

## What a hit does not promise

A cache hit means *this scanner, at this version, with this data, over this exact input, said
this*. It does not mean the artefact is still safe. A vulnerability disclosed an hour ago is not in
a report from yesterday, however unchanged the input.

That is why caching is opt-in and time-bounded rather than on by default, and why the tool-data
version is folded into the key. It is also why a TTL is a real answer to a real question and not
just housekeeping: it bounds how stale a passing verdict is allowed to be.

## Adding a scanner? Two things to get right

1. **Implement `CacheVersioner` if your answer depends on downloaded data.** Otherwise a database
   refresh leaves every cached entry describing the old one, and nothing says so.
2. **Implement `Prewarmer` if that data is expensive to fetch**, so the fan-out does not fetch it
   many times at once.

Both are optional interfaces, which means forgetting them is silent — the scanner works, and only
its cache behaviour is wrong. See [adding a scanner](extending/scanner.md).
