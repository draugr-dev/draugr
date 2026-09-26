---
title: Report schema
description: Every property a finding and a run carry in Draugr's SARIF and report.json, for anything reading them programmatically.
section: Reference
order: 35
---

# Report schema

What a Draugr report contains, field by field, for a gate or a dashboard reading it rather than a
person. How to produce and deliver one is [render a report and send it
somewhere](../guides/reports-and-publishers.md).

## Telling a partial run from a clean one

A gate reading `report.json` should check more than `verdict`. A run where a scanner never started
and a run that found nothing both produce findings-shaped output, and the difference is what your
pipeline should do about it. One is broken infrastructure, the other is work.

| Field | Meaning |
|---|---|
| `controls[].scanErrors` | what stopped that control, in the scanner's own words. Its counts then describe what the scanners that *did* run found, which is not the same as what is there. A control that produced nothing at all is still listed, with `"verdict": "fail"` and no counts. |
| `notMeasured[]` | a scanner that was planned and then not run because it could not answer the question its target asked, the control, scanner, component and reason. Not an error: nothing went wrong, and no `scanErrors` are recorded for it. |
| `dependencyFiles[]` | per component and control, the dependency files the scanners that list their inputs read packages from (`read`, a count) and the ones none of them did (`unread[]`: `repository`, `path` and `reason`). A reason is `no lockfile`, `no pinned versions` or `no packages read`. The packages such a file declares were not checked. An `iac` entry lists the Terraform files calling a module Trivy could not load, with `read` at 0 and a reason such as `module "vpc" not loaded`; the resources that module defines were not checked. |

`scanErrors` and `notMeasured[]` are omitted when there is nothing to report, so a clean run's
document is unchanged. `dependencyFiles[]` is present whenever a scanner that lists its inputs ran,
and an entry with no `unread` means every dependency file was read.

```bash
draugr scan draugr.saga.yaml -o out/
jq -e '[.controls[].scanErrors // empty] | length == 0' out/report.json   # fail the build on a partial run
jq -e '[.dependencyFiles[]?.unread // empty] | length == 0' out/report.json   # fail on a file no scanner read
```

## What each finding carries

Draugr reports as one SARIF tool, so every finding keeps its own attribution in its property bag:

| Property | What it says |
|---|---|
| `control` | The check that produced it, `sca`, `sast`, `secrets`, `iac`, `images`, `licenses` |
| `tool` | The scanner that found it, `trivy`, `semgrep`, `gitleaks` |
| `component` | The part of the application it belongs to |
| `repository` | Which repository it was found in, for a component holding more than one |
| `priority` | The band Draugr computed from that component's exposure and criticality |
| `exposure`, `criticality` | That component's declared classification, the two inputs to the band that do not come from the scanner |
| `security-severity` | The numeric score, where the scanner gave one |
| `escalation` | Why the band is higher than the severity: the dataset, the fact, and the day it was fetched |
| `reachability` | Whether your code can reach the vulnerable code, which analyzer decided, and how |
| `historical` | `true` on a finding from a commit in the repository's history. Absent on a finding from the current tree. The location is the path the file had in that commit |

`control` and `tool` answer different questions, and both matter to anything grouping findings:
one rule id reported by two controls is two separate things to do.

**`exposure` and `criticality` are what makes the band arithmetic checkable.** Priority folds a
component's classification into the scanner's severity, so the same CVE is P1 on an internet-facing
service and P3 on a restricted one. Naming the component is not the same as stating that premise:
without these two, reconstructing a band means fetching the descriptor, and the descriptor in the
repository today is not necessarily the one that produced this finding. Both are empty for a
project-scoped finding, which belongs to no one component, and for a component that declares
neither, which Draugr reads as public and critical so that an unclassified component surfaces rather
than hides.

**`escalation` and `reachability` are why a band is not what the severity alone would give.** One
moves a finding up and one moves it down, and both carry the evidence rather than only the verdict,
the analyzer and method for reachability, the dataset and the date for escalation. A reader is told
to reject a reachability claim that does not say how it was reached; the same standard applies to a
claim that something is more urgent than its score.

**`historical: true` marks a finding from the repository's commit history.** Its location is the
path the file had in the commit that introduced the secret, which a file renamed or deleted since
no longer has. The credential is still readable by anyone who can clone the repository, so a
historical finding needs rotating like a tree one. A secret present in both the tree and the history
is reported once, as the tree finding. Each entry in `report.json`'s `findings` carries the same
`historical` field.

## What the cache contributed

A finding can come from a cache rather than from a scan, and `stats.cache` says what that rests on.

```jsonc
"cache": {
  "enabled": true,
  "dir": "/home/runner/.cache/draugr",
  "ttl": "24h0m0s",
  "readOnly": false,
  "hits": 12,
  "oldestHit": "2026-08-31T04:11:02Z",
  "unpinned": ["ghcr.io/acme/api:1.4.2"]
}
```

| Field | What it says |
|---|---|
| `enabled` | whether a cache was in use at all. Always present, because a run told not to cache and a run whose every entry expired both report zero hits, and a missing key is not an answer |
| `dir` | the directory as it was given, neither resolved nor probed. Enough to tell a CI cache from a laptop's; what restored an archive into it is the pipeline's fact rather than the scan's |
| `ttl` | how long an entry stays usable. Absent when there is no expiry, which `--cache-ttl 0` selects and which means a hit has no upper bound on its age |
| `readOnly` | a cache this run served from and did not write to |
| `hits` | the same number as `cacheHits`, beside the caveats that qualify it |
| `oldestHit` | when the oldest reused entry was written. An instant rather than an age, because a duration is true only at the moment it is computed and a kept report is read later |
| `unpinned` | targets whose reused result could not be content-addressed, today images named by a tag alone. Such a hit is right about its key and possibly wrong about the image: the tag can have been rebuilt since, and nothing in the reused report says so |

A gate that re-runs when results are too old has everything it needs here:

```bash
jq -e '.stats.cache.enabled and (.stats.cache.unpinned // [] | length == 0)' out/report.json
```

## What the run carries

Some statements are about the scan rather than about any one finding, and those live in the run's
own property bag:

| Property | What it says |
|---|---|
| `draugr/provenance` | What each scanner said about its own run, the standard applied, the scope, how much of it could be decided |
| `decided` | The classifications this run settled, whether or not a finding resulted |
| `consulted` | The exploitability datasets the run had loaded: the signal, the day the copy was obtained, whether it was older than the run's `maxAge`, how many records it held, the EPSS threshold, and what set it |

**`decided` and `consulted` both exist to separate "looked and found nothing" from "never
looked."** A scanner that reports nothing about a control has either examined it and been
satisfied or never examined it; `escalation` appears on a finding only when a signal *raised* it,
so its absence covers a CVE that is not listed, one that is listed but was already at the top
band, and a dataset nobody loaded at all.

Without `consulted`, anything explaining a priority, a dashboard, a pull-request comment, a person
reading the file, cannot tell *not on KEV* from *KEV was not consulted*, and silence reads as the
second. `asOf` is empty when you supplied a feed file by hand, which has no fetch to record;
`entries` is there because a dataset that loaded and turned out to be empty answers every lookup
with "not listed" and looks exactly like one that is working. `stale` is `true` when the copy was
older than the run's `maxAge` when it was read, and absent otherwise; the run is the only reader
that knew the limit.

`thresholdFrom` names what set the EPSS threshold, `the default`,
`config.exploitability.epssThreshold`, or `--epss-threshold`. The number alone is the one input to
an escalation that arrives anonymous: the dataset names itself and the day its copy was obtained,
while the line a score was measured against does not say who drew it. Whether a band is a policy or
an accident depends on the answer.

A run that loaded no exploitability data writes no `consulted` block at all.

The `sarif` report is also what your editor reads. See [see findings in your
editor](../guides/findings-in-your-editor.md) for inline diagnostics in VS Code and JetBrains.

For the exact schema of `config.publishers`, see the
[Saga schema](../reference/saga-schema.md#configpublishers); for the full
catalog of reporters and publishers, see the
[integrations catalog](../reference/catalog.md#reporters).
