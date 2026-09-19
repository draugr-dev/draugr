---
title: Reducing the noise
description: Every lever Draugr gives you for turning a wall of findings into a short list, what each one does to the number, and the order to reach for them in.
section: Core concepts
order: 35
---

# Reducing the noise

A scan of a real project returns hundreds of findings. Most of them are true, few of them are
yours to fix this week, and the gap between those two facts is the whole problem.

Draugr gives you a lot of ways to close it, and they are described in full on the pages linked
from each row below. This page exists so you can find out that a lever exists at all, and see what
it does to the number before going to read about it.

## Contents

- [Start here](#start-here)
- [Levers that rank](#levers-that-rank)
- [Levers that remove](#levers-that-remove)
- [Levers that narrow](#levers-that-narrow)
- [What the marks in the output mean](#what-the-marks-in-the-output-mean)
- [Reading a count you can trust](#reading-a-count-you-can-trust)

## Start here

**Declare `exposure` and `criticality` on your components.** Everything else on this page is a
refinement of a ranking, and without these two the ranking is severity alone.

```yaml
components:
  - name: api
    exposure: public          # public · authenticated · internal · restricted
    criticality: important    # critical · important · supporting
```

Two lines, in the descriptor, where a reviewer sees them in the pull request. They are the only
inputs on this page that no scanner can compute, because they are facts about your architecture
and your business rather than about your code. Draugr combines them with each finding's severity
through two published tables to produce a band, P1 to P4.

With nothing declared, every component reads as public and critical, which is the most severe
reading, and the report says so. That is a deliberate default and a bad ranking. See
[Prioritization](prioritization.md).

## Levers that rank

These change the order. Nothing is hidden, and the count stays the same.

| Lever | What it does | Where |
|---|---|---|
| `exposure` × `criticality` × severity | produces the P1–P4 band every other lever refers to | [Prioritization](prioritization.md) |
| **KEV** | a vulnerability on CISA's Known Exploited catalog is escalated to critical | [Prioritization](prioritization.md#exploitability-kev-and-epss) |
| **EPSS** | a prediction at or above your threshold raises the severity one band | [Prioritization](prioritization.md#exploitability-kev-and-epss) |
| **Reachability** | a vulnerability your code cannot reach is ranked down | [Saga schema](../reference/saga-schema.md#reachability-for-go) |
| **Control floor** | a control insists on a minimum, so a committed private key is never a warning | [Prioritization](prioritization.md) |

KEV and EPSS are enrichment, turned on under `config.exploitability`, and they read a local cache
that `draugr feeds update` fills. That is deliberate: a scan that reaches the network mid-run
cannot be reproduced, and the report records which copy of each feed it consulted, and when.

## Levers that remove

These make the number smaller. Each one leaves a record of what it removed and why, because a
finding that vanishes is indistinguishable from one that was never made.

| Lever | What it does | Where |
|---|---|---|
| **Correlation** | one flaw found by three scanners is one row, not three, and the row names the others | [Controls & scanners](controls-and-scanners.md) |
| **`config.exclude`** | you accept a finding, with a reason, an author and an expiry date | [Saga schema](../reference/saga-schema.md#configexclude) |
| **VEX** | your supplier states a vulnerability does not affect their product, and you import that | [Saga schema](../reference/saga-schema.md#reading-a-suppliers-vex-componentsvex-configvexsources) |
| **Source directives** | a scanner honored a comment somebody wrote in the code | counted apart, see below |
| **Actions** | findings collapse into the decisions that clear them, so six CVEs in one package are one upgrade | [What to fix first](what-to-fix-first.md) |
| **`builtBy` / `operatedBy`** | a finding nobody on your team can act on is named as somebody else's | [What to fix first](what-to-fix-first.md) |

The three acceptance routes are counted apart in every report, and the distinction is the point.
`config.exclude` is a decision somebody here signed. VEX is an assertion whose author you can ask
about. A source directive was written by whoever was editing the file, carries no author and no
date, and is the weakest of the three. A single total could only report the weakest.

## Levers that narrow

These change what you are shown without changing what was found. The counts always describe the
whole run, and the report says when a listing is filtered.

| Lever | What it does |
|---|---|
| `--min-priority P2` | list only the bands worth acting on now |
| `--top 0` | every finding rather than the first ten |
| `--view actions` | a row per thing to do instead of a row per finding |
| `--view compact` | one line each, to see how much there is |
| `--components`, `--controls` | scan one part of the application |
| `--exposure`, `--criticality`, `--labels` | scan the components matching a classification |
| `draugr diff` | only what this change introduced, against a report from before it |
| `gate.failOn`, per-control thresholds | decide which band fails the build, per control |

`draugr diff` is the one most teams reach for last and benefit from most. A pull request that adds
no findings is a pull request nobody has to read a report for, whatever the project's standing
total is.

## What the marks in the output mean

A finding whose band is not what its severity alone would give it carries a mark saying which
lever moved it:

| Mark | Means |
|---|---|
| `↑ KEV` | on CISA's Known Exploited Vulnerabilities catalog |
| `↑ EPSS` | predicted exploitation at or above your threshold |
| `↑ floor` | a control insists this kind of finding is never lower |
| `↓ unreachable` | analysis found no path from your code to it |
| `↩ history` | describes a commit rather than the current tree, so its path may be gone |

A finding with no mark was ranked by exposure, criticality and severity alone.

## Reading a count you can trust

Every number in a Draugr report is auditable, and the levers above are why that matters. A count
that got smaller because somebody accepted twelve findings and a count that got smaller because
twelve findings were fixed are different facts, and a report that cannot tell them apart is a
report nobody should gate on.

So:

- **Accepted findings stay in the report**, marked, with the reason and whoever gave it.
- **The three acceptance routes are counted separately**, never folded into one total.
- **A rule that suppressed nothing is reported**, because an exclusion doing nothing looks exactly
  like one that is working.
- **An exclusion past its expiry stops suppressing** and the report says so, rather than letting a
  finding reappear with nothing to explain it.
- **A filtered listing says it was filtered**, and the counts still describe the whole run.
- **The feeds are named with their fetch time**, so a verdict that turned on KEV can be re-checked
  against the same copy of KEV.

None of these makes the number smaller. They are what makes the smaller number worth something.
