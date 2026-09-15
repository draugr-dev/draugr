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

Both are omitted when there is nothing to report, so a clean run's document is unchanged.

```bash
draugr scan draugr.saga.yaml -o out/
jq -e '[.controls[].scanErrors // empty] | length == 0' out/report.json   # fail the build on a partial run
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

## What the run carries

Some statements are about the scan rather than about any one finding, and those live in the run's
own property bag:

| Property | What it says |
|---|---|
| `draugr/provenance` | What each scanner said about its own run, the standard applied, the scope, how much of it could be decided |
| `decided` | The classifications this run settled, whether or not a finding resulted |
| `consulted` | The exploitability datasets the run had loaded: the signal, the day the copy was obtained, how many records it held, the EPSS threshold, and what set it |

**`decided` and `consulted` both exist to separate "looked and found nothing" from "never
looked."** A scanner that reports nothing about a control has either examined it and been
satisfied or never examined it; `escalation` appears on a finding only when a signal *raised* it,
so its absence covers a CVE that is not listed, one that is listed but was already at the top
band, and a dataset nobody loaded at all.

Without `consulted`, anything explaining a priority, a dashboard, a pull-request comment, a person
reading the file, cannot tell *not on KEV* from *KEV was not consulted*, and silence reads as the
second. `asOf` is empty when you supplied a feed file by hand, which has no fetch to record;
`entries` is there because a dataset that loaded and turned out to be empty answers every lookup
with "not listed" and looks exactly like one that is working.

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
