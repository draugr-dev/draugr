---
title: Run Draugr air-gapped
description: One way to say offline, what Draugr fetches and when, and how to prepare a runner with no network.
section: Guides
order: 70
---

# Run Draugr air-gapped

Draugr reaches out from a handful of places. `--offline` — or `DRAUGR_OFFLINE=1` — says once that
this machine has no network, and every one of them honours it.

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
| `draugr feeds update` | the CISA KEV catalog and the FIRST EPSS scores |
| `draugr self-update` | the latest Draugr release |
| `draugr doctor` | the latest Draugr release, to compare against yours |
| a scan, before it starts | Trivy's vulnerability database and Nuclei's template set |
| a scan, per target | the registry, for an image; the endpoint itself, for a host or DAST target |

The last row is the one `--offline` cannot help with. Scanning a remote image or probing a live
endpoint *is* a network operation — if a target is unreachable, the control reports an error
rather than a pass.

## Preparing a runner

Do this once, on a machine that has a network, and copy `~/.draugr` across.

```bash
draugr tools install            # binaries and their data into ~/.draugr/bin
draugr feeds update             # KEV and EPSS into ~/.draugr/feeds
trivy image --download-db-only  # Trivy's vulnerability database, into its own cache
nuclei -update-templates        # Nuclei's template set, if you run dast
```

**Trivy's database and Nuclei's templates live in their own caches, not in `~/.draugr`.** Copy
those too — `~/.cache/trivy` and `~/.local/nuclei-templates` by default, both relocatable with
`TRIVY_CACHE_DIR` and `NUCLEI_TEMPLATES_DIR`.

A scan with `--offline` and no Trivy database does not silently return "no vulnerabilities". The
control reports an error and the run fails:

```
INFO   offline: not refreshing scanner data, using what is on disk
  sca  ERROR  did not run
       run trivy-fs: … --skip-db-update cannot be specified on the first run
```

That is the intended behaviour: a scanner that could not run has found nothing, and nothing found
is not the same as nothing there.

## Exploitability feeds

`--kev cache` and `--epss cache` read `~/.draugr/feeds` and never touch the network, which is what
you want on a runner whether or not it has one. `auto` fetches when the cache is stale — offline
turns that off, so it reads the cache or says clearly there is nothing to read.

A copy older than `config.exploitability.maxAge` is used and reported as stale rather than
refused; on a deliberately pinned runner, raise `maxAge` so a reproducible verdict does not come
with a warning every run. See
[`config.exploitability`](../reference/saga-schema.md#configexploitability).

## Descriptors that name remote fragments

A Saga can assemble itself from [fragments](saga-fragments.md), and a fragment held in another
repository has to be fetched. Offline, that is refused rather than skipped — a fragment that
cannot be read is scope the descriptor claims and the run would not have, and a scan quietly
covering less than it says is worse than one that stops.

Resolve it on a connected machine and carry the flattened descriptor across instead:

```bash
# connected
draugr validate azure.saga.yaml --resolved > acme.flat.saga.yaml

# air-gapped
draugr scan acme.flat.saga.yaml
```

The flattened copy contains every component and exclusion the fragments contributed, with each
remote one recorded at the commit it resolved to — so it is reproducible as well as portable, and
the provenance survives the crossing as comments.

## Keeping it that way

`--offline` is a promise you can check. Run the scan on a host with no route out and it either
works or tells you exactly which fetch it needed — which is a better test than trusting the flag,
and the one worth putting in CI for an air-gapped environment.

Two narrower opt-outs remain, for a machine that *does* have a network:

- `draugr doctor --offline` skips only the release check.
- `DRAUGR_NO_UPDATE_CHECK=1` does the same, for someone who does not want to be told about
  releases but is otherwise online.

## Related

- [Caching and performance](caching-and-performance.md) — what a scan reuses between runs.
- [Prioritization](../concepts/prioritization.md#exploitability-kev-and-epss) — KEV and EPSS, and
  what a stale feed costs you.
- [CLI reference](../reference/cli.md) — every flag, including `draugr feeds`.
