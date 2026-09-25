---
title: Run Draugr air-gapped
description: One way to say offline, what Draugr fetches and when, and how to prepare a runner with no network.
section: Guides
order: 70
---

# Run Draugr air-gapped

Draugr reaches out from a handful of places. `--offline`, or `DRAUGR_OFFLINE=1`, says once that this
machine has no network, and every one of Draugr's own fetches honors it.

**Three scanners cannot run without a network at all**, and that is a property of the tools rather
than a setting. They are named below. Most readers of this page are not disconnected but behind an
egress allowlist, and for them the useful list is the hosts rather than the flag: `draugr doctor`
prints it.

```bash
draugr scan draugr.saga.yaml --offline
DRAUGR_OFFLINE=1 draugr scan draugr.saga.yaml
```

Offline never fails quietly. Where a fetch was optional it is skipped, with a line saying so.
Where it was the whole point of the command, the command refuses and names what it would have
downloaded.

## What Draugr fetches, and when

`draugr doctor` prints this list on any machine, so you don't have to keep it:

| When | What |
|------|------|
| `draugr tools install` | each tool's pinned release archive, verified against a recorded SHA-256 |
| `draugr feeds update` | the CISA KEV catalog, the FIRST EPSS scores and the Go vulnerability database |
| `draugr self-update` | the latest Draugr release |
| `draugr doctor` | the latest Draugr release, to compare against yours |
| a scan, before it starts | the reference data each scanner reads, warmed once for the whole run |
| a scan, per target | the registry, for an image; the endpoint itself, for a host or DAST target |

The last row is the one `--offline` cannot help with. Scanning a remote image or probing a live
endpoint *is* a network operation. If a target is unreachable, the control reports an error rather
than a pass.

## Preparing a runner

Do this once, on a machine that has a network, and copy `~/.draugr` across.

```bash
draugr tools install --all      # binaries and their data into ~/.draugr/bin
draugr feeds update             # KEV, EPSS and the Go vulnerability database into ~/.draugr/feeds
trivy image --download-db-only  # Trivy's vulnerability database, into its own cache
grype db update                 # Grype's vulnerability database, if you run it
nuclei -update-templates        # Nuclei's template set, if you run dast
```

A runner that serves one project can carry less: `draugr tools install --saga <descriptor>` fetches
the tools that descriptor's scan will run, and `--offline` names the archives it would have needed
so the list can be assembled somewhere with a network.

```bash
retire --path /tmp/empty --cachedir ~/.draugr/data/retirejs   # retire.js advisory database, if you run sca
```

**Most of these live in their own caches, not in `~/.draugr`.** Copy those too, `~/.cache/trivy`,
`~/.cache/grype` and `~/.local/nuclei-templates` by default, all relocatable with
`TRIVY_CACHE_DIR`, `GRYPE_DB_CACHE_DIR` and `NUCLEI_TEMPLATES_DIR`. retire.js is the exception:
Draugr already points it under `~/.draugr/data`, and passes `--jsrepo` at that copy when offline.

**The `iac` control needs nothing copied.** Offline, Draugr passes `--skip-check-update` and Trivy
evaluates the misconfiguration checks built into the pinned release instead of fetching the checks
bundle.

## What cannot run offline

Semgrep fetches its default rule pack on every invocation, with no cache to prepare.

| Scanner | What it fetches | From |
|---|---|---|
| `semgrep` | the `p/default` rule pack | `semgrep.dev` |

Semgrep can be pointed at rules on disk with its own `config` option, which is the way to run
`sast` without the registry. Under `--offline`, a scan that leaves `config` unset or names a
registry ruleset does not reach `semgrep.dev`, and the `sast` control reports an error naming
`config.controls.sast.semgrep.config` instead.

`draugr doctor` lists every host a scan contacts, and marks which are fetched per scan rather than
warmed once, so the distinction is visible before a pipeline is written rather than after it fails.

**Grype refuses a database older than five days**, and copying one across takes time the clock
keeps counting. `GRYPE_DB_UPDATE_URL` points it at an internal mirror so a runner refreshes from
inside your network instead. Raising `GRYPE_DB_MAX_ALLOWED_BUILT_AGE` is the other lever and the
worse one: it buys quiet by letting the scan run against data that has stopped being updated, and
a pass earned that way is the failure this tool exists to prevent.

A scan with `--offline` and no Trivy database does not silently return "no vulnerabilities". The
control reports an error and the run fails:

```
INFO   offline: not refreshing scanner data, using what is on disk
  sca  ERROR  did not run
       run trivy-fs: … --skip-db-update cannot be specified on the first run
```

That is the intended behavior: a scanner that could not run has found nothing, and nothing found
is not the same as nothing there.

## govulncheck

govulncheck reads the copy of the Go vulnerability database that `draugr feeds update` leaves in
`~/.draugr/feeds/govulndb`, and only after checking it. A copy is refused when it was fetched longer
ago than [`config.exploitability.maxAge`](../reference/saga-schema.md#configexploitability) (24h by
default), or when its `index/db.json` or `index/modules.json` is missing, unreadable or empty.
govulncheck reports "No vulnerabilities found" and exits 0 against an empty or stale database, so
an unchecked copy could read as a clean result.

With `--offline` and no usable copy, the control reports an error naming the check that failed:

```
  sca  ERROR  3 P1
       govulncheck: cannot run offline: local Go vulnerability database fetched 2026-09-20 00:00 UTC,
         older than 24h; run `draugr feeds update govulndb`
```

The age is measured from the fetch, and copying `~/.draugr` to a runner keeps that date. Refresh the
copy within `maxAge`, or raise `maxAge` on a runner deliberately pinned to a known copy. The
evidence names the database a run read, under `database`.

## Exploitability feeds

`--kev cache` and `--epss cache` read `~/.draugr/feeds` and never touch the network, which is what
you want on a runner whether or not it has one. `auto` fetches when the cache is stale. Offline
turns that off, so it reads the cache or says clearly there is nothing to read.

A copy older than `config.exploitability.maxAge` is used and reported as stale rather than
refused; on a deliberately pinned runner, raise `maxAge` so a reproducible verdict does not come
with a warning every run. See
[`config.exploitability`](../reference/saga-schema.md#configexploitability).

## Descriptors that name remote fragments

A Saga can assemble itself from [fragments](saga-fragments.md), and a fragment held in another
repository has to be fetched. Offline, that is refused rather than skipped, a fragment that cannot
be read is scope the descriptor claims and the run would not have, and a scan quietly covering less
than it says is worse than one that stops.

Resolve it on a connected machine and carry the flattened descriptor across instead:

```bash
# connected
draugr validate azure.saga.yaml --resolved > acme.flat.saga.yaml

# air-gapped
draugr scan acme.flat.saga.yaml
```

The flattened copy contains every component and exclusion the fragments contributed, with each
remote one recorded at the commit it resolved to, so it is reproducible as well as portable, and the
provenance survives the crossing as comments.

## Keeping it that way

`--offline` is a promise you can check. Run the scan on a host with no route out and it either works
or tells you exactly which fetch it needed, which is a better test than trusting the flag, and the
one worth putting in CI for an air-gapped environment.

Two narrower opt-outs remain, for a machine that *does* have a network:

- `draugr doctor --offline` skips only the release check.
- `DRAUGR_NO_UPDATE_CHECK=1` does the same, for someone who does not want to be told about
  releases but is otherwise online.

## Related

- [Caching and performance](caching-and-performance.md), what a scan reuses between runs.
- [Prioritization](../concepts/prioritization.md#exploitability-kev-and-epss), KEV and EPSS, and
  what a stale feed costs you.
- [CLI reference](../reference/cli.md), every flag, including `draugr feeds`.
