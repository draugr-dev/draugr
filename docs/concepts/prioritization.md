---
title: Prioritization
description: How exposure, criticality, and severity combine into a P1–P4 priority band.
section: Core concepts
order: 30
---

# Prioritization: what to fix first

Severity isn't priority. A `scan` can return a wall of "high" findings, but which one you
fix first depends on **where it lives**. Declare two attributes on a component and Draugr
ranks every finding into a band **P1–P4**:

- **`exposure`** (`public` → `authenticated` → `internal` → `restricted`) — how reachable the
  component is. This drives *likelihood*.
- **`criticality`** (`critical` → `important` → `supporting`) — the business impact if it
  fails. This drives *impact*.

A finding's **normalized severity** (from its CVSS score, or its SARIF level, or a
control floor) combines with the component's `exposure × criticality` through two small
lookup matrices to yield the priority. So the *same* CVE is P1 on a public, business-critical
gateway and P3 on an internal dev tool — same finding, different risk.

Both matrices are printed in full below, with four findings worked through them.

**Exploitability enrichment (optional).** Severity can be raised by real-world signals before
ranking — see **Exploitability: KEV and EPSS** below.

- **Focus:** `--min-priority P2` lists only the findings worth acting on now
  (P1 = act now · P2 = this cycle · P3 = backlog · P4 = track).
- **Gate:** `--fail-on-priority P1` fails the build on any P1 — component-aware gating with no
  per-component config.
- A component left **unclassified** is treated as high-risk, so nothing slips silently.

Set `exposure` and `criticality` by hand (see the [Saga schema](../reference/saga-schema.md))
or with the guided [`draugr classify`](../reference/cli.md#draugr-classify-sagayaml--directory) wizard.

## The two matrices

Nothing here is inferred at runtime. These are the shipped defaults
(`pkg/prioritization/prioritization.go`), and a descriptor can override individual cells.

### Two different meanings of "critical"

`critical` is a value on both axes and means something different on each. It is the one thing worth
pinning before reading the tables.

| | describes | values |
| --- | --- | --- |
| `criticality` | the **component** — how much the organization depends on it | `critical` · `important` · `supporting` |
| `severity` | the **flaw** — how much harm it could cause if exploited | `critical` · `high` · `medium` · `low` |

`criticality: critical` says the organization depends on this component. `severity: critical`
says this flaw could cause serious harm if it were exploited. Neither implies the other: a
component the organization depends on carries low-severity findings like anything else, and a
supporting one can carry a critical flaw.

The two meet in step 2 — a critical component with a critical finding is P1, and the same critical
component with a low finding is P3. Each table below names its row axis and its column axis for
that reason.

### Step 1 — the component's context tier

What the descriptor declares about the component, crossed into one of four tiers. This step does
not look at the finding at all.

**Rows are `exposure`. Columns are `criticality`.**

| exposure | `critical` | `important` | `supporting` |
| --- | --- | --- | --- |
| `public` | C1 | C1 | C2 |
| `authenticated` | C1 | C2 | C3 |
| `internal` | C2 | C3 | C4 |
| `restricted` | C3 | C4 | C4 |

### Step 2 — the band

The tier crossed with the finding's normalized severity.

**Rows are the tier from step 1. Columns are `severity`** — the flaw's own badness, not the
component's importance.

| tier | `critical` | `high` | `medium` | `low` |
| --- | --- | --- | --- | --- |
| C1 | **P1** | **P1** | P2 | P3 |
| C2 | **P1** | P2 | P2 | P3 |
| C3 | P2 | P3 | P3 | P4 |
| C4 | P2 | P3 | P4 | P4 |

Both are monotonic: raising exposure, criticality or severity never lowers a band. Of the 48
combinations, **9 land in P1 and 9 in P4**. P1 is deliberately scarce — a band that a third of
findings reach is not a queue anybody works from.

### Where the severity in step 2 comes from

A scanner reporting a CVSS score is banded on the standard v3 ranges:

| score | severity |
| --- | --- |
| 9.0 – 10.0 | `critical` |
| 7.0 – 8.9 | `high` |
| 4.0 – 6.9 | `medium` |
| below 4.0 | `low` |

A finding with no score — a secret, a static-analysis rule, an IaC check — is banded from the SARIF
level instead: `error` is high, `warning` is medium, `note` and `none` are low.

### Four findings, worked through

**A P1.** `CVE-2021-44228` scores 10.0, so its **severity** is `critical`. The component declares
`exposure: public` and `criticality: critical` — it is one the organization depends on — so its
tier is **C1**. C1 crossed with a critical severity = **P1**. Both `critical`s are in play here,
and they are answering different questions.

**Another P1, from a lower score.** A CVE scoring 7.5 is `high`, not critical. On the same public,
business-critical component the tier is still C1, and C1 × high = **P1**. A high on something
public and depended on outranks a critical on something nobody can reach.

**The same 10.0, two bands lower.** Put `CVE-2021-44228` on a component declaring
`exposure: internal` and `criticality: important`. The tier is **C3**, and C3 × critical = **P2**.
Nothing about the flaw changed; the answer to "how much does this matter here" did.

**A P4.** A CVE scoring 3.7 is `low`. On `exposure: restricted` and `criticality: supporting` the
tier is **C4**, and C4 × low = **P4**. Still reported, still counted, and not something to
interrupt anybody for.

### An unclassified component

A component that declares neither field is read as **`public` and `critical`** — tier C1, the most
concerning. An unclassified component surfaces rather than hides, and both rows read `not declared`
in the report so the band is traceable to the gap that produced it.

The fix is a descriptor edit rather than an argument with the tool.

## Exploitability: KEV and EPSS

CVSS says how bad a vulnerability *could* be in the abstract. It says nothing about whether
anyone is actually exploiting it. Two public datasets close that gap, and Draugr folds either
into a finding's severity **before** it is ranked — so "what to fix first" reflects the real
world, not just the theory. New to these? [EPSS & KEV explained](/learn/epss-and-kev/) covers
the concepts; this page covers using them.

| Signal | What it is | Effect on a matching finding |
|--------|------------|------------------------------|
| **KEV** | CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog — CVEs with *confirmed, observed* exploitation | severity becomes **critical**, whatever it was |
| **EPSS** | FIRST's [Exploit Prediction Scoring System](https://www.first.org/epss/) — a daily 0–1 probability that a CVE will be exploited in the next 30 days | severity is raised **one band** (low→medium→high→critical) when the score is at or above `--epss-threshold` |

KEV wins where both apply: observed exploitation outranks a prediction about it.

### Using them

Turn it on in the descriptor, where it gets reviewed:

```yaml
config:
  exploitability:
    kev: cache          # path | cache | auto
    epss: cache
    epssThreshold: 0.5  # optional; the default
    maxAge: 24h         # optional; how old a cached feed may be
```

```bash
draugr feeds update                    # into ~/.draugr/feeds
draugr scan draugr.saga.yaml           # enrichment is on, no flags to remember
```

In the Saga rather than only in flags because it is a decision about how findings are ranked. A
team that agrees to use KEV needs somewhere to write that down that a reviewer sees and every
pipeline reads — not a flag whoever wrote the workflow has to remember.

**`--kev` and `--epss` still work and override the descriptor**, which is what you want for a
one-off:

```bash
draugr scan draugr.saga.yaml --kev cache --epss cache      # without a descriptor entry
draugr scan draugr.saga.yaml --epss-threshold 0.1          # widen the net for this run only
```

Only a flag you actually type overrides — passing `--epss-threshold 0.5` beats a descriptor that
says `0.1`, and not passing it leaves the descriptor's value alone. See
[`config.exploitability`](../reference/saga-schema.md#configexploitability) for the full block.

**A scan never fetches on its own.** `cache` reads what `feeds update` left and cannot reach the
network, so there is no network dependency inside your pipeline, nothing leaves your environment
about what you are scanning, and the same inputs produce the same verdict. That is the same
guarantee the bring-your-own-file route has always given; it just no longer requires you to
know two URLs.

`draugr feeds status` says what is cached, how old it is, and the digest of each copy:

```
FEED   FETCHED                AGE            SIZE       DIGEST
kev    2026-08-01 09:12Z      6 hours        1.5 MiB    sha256:15b44d7c9c57
epss   2026-07-29 08:55Z      3 days (stale) 10.3 MiB   sha256:41c20e9dc3cf
```

**In CI, make the fetch its own step.** A feed outage then fails where it happened, loudly,
instead of producing a scan that ranked everything as though nothing were exploited:

```yaml
- run: draugr feeds update
- run: draugr scan draugr.saga.yaml --kev cache --epss cache
```

**Working locally**, `auto` saves you remembering: it reads the cache when it is fresh and
fetches when it is missing or more than a day old.

```bash
draugr scan draugr.saga.yaml --kev auto --epss auto
draugr scan draugr.saga.yaml --epss auto --epss-threshold 0.1   # widen the net
```

If a fetch fails and there is a cached copy, the scan uses it and says so rather than failing —
a feed outage should not break a gate that has a usable answer on disk. With nothing cached, it
is an error: you asked for enrichment and did not get it, and a run that quietly skips
escalation is worse than one that stops.

### What the report says about it

A run that used exploitability data says so, says which copy, and says what it changed:

```
Exploitability: KEV 2026-08-01 · EPSS 2026-08-02 — 3 findings raised
```

**"nothing raised" is printed when nothing moved**, because that is a result rather than an
absence. Without it, the only way to learn that a feed changed nothing is to read every finding
looking for a note that is not there, and then wonder whether you missed one.

The count is over the whole run, not the visible listing — `--top` and `--min-priority` narrow
what is shown, and this answers what the feeds did, not what fitted on the page.

Each finding that was actually moved carries the reason underneath it:

```
  P1  high  8.1  CVE-2024-3094   sca  trivy  go.mod:12
      xz: malicious code in the upstream tarballs
      ↑ ranked as critical — on KEV (2026-08-01)
```

**The Severity column keeps showing what the scanner said.** Enrichment feeds the ranking rather
than rewriting the scanner's rating, so a finding can be `high` and still be P1 — and the note is
what explains it. Overwriting the scanner's number would leave nothing to compare against and no
way to see that a signal was applied at all.

This is the difference between evidence and a hint. A P1 on its own is a conclusion with the
premise withheld; *ranked as critical because CISA listed it on a date you can check* is
something a reader can verify, disagree with, or reproduce six months later.

Findings nothing moved carry no note, so the note means something when it appears. The same
information is in the markdown and HTML reports, and in `--format json` and `--format sarif`
under `escalation` on each finding, with the feeds themselves under `exploitability`.

A **stale** feed is marked in the report rather than only warned about while the scan ran — the
logs of the run that produced a report are exactly where nobody looks six weeks later.

### Staleness

EPSS is republished daily. A stale copy does not fail — it ranks a finding lower than today's
data would, which is the failure mode that looks like success. So a scan reading a feed more
than a day old warns and names the age:

```
WARN using a stale exploitability feed feed=epss fetched_at=2026-07-29T08:55:00Z age="3 days"
```

`draugr feeds update` refreshes it; a daily job is plenty. Raise `config.exploitability.maxAge`
on a runner deliberately pinned to a known copy of the data — reproducing last quarter's verdict
requires last quarter's feed, and being told it is old every time helps nobody.

### Bring your own file

`--kev` and `--epss` still take a path, which is the air-gapped route and needs no cache at all:

```bash
curl -fsSL -o kev.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl -fsSL https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | gunzip > epss.csv

draugr scan draugr.saga.yaml --kev kev.json --epss epss.csv
```

`--kev` takes CISA's JSON as published; `--epss` takes FIRST's CSV (`cve,epss,percentile` —
comment and header lines are skipped). Either signal works on its own, and each accepts a path,
`cache`, or `auto` — in the descriptor or on the command line.

Setting `DRAUGR_OFFLINE=1` stops `auto` fetching anything: it reads the cache, or says clearly
that there is nothing to read.

### Choosing an EPSS threshold

`--epss-threshold` defaults to **0.5**: a coin-flip chance of exploitation within 30 days. That
is a deliberately high bar. EPSS scores are heavily skewed — most CVEs sit far below 0.01 — so
lowering the threshold widens the net faster than the number suggests.

| Threshold | Roughly means | Use when |
|-----------|---------------|----------|
| `0.5` (default) | very likely to be exploited | you want few, high-confidence escalations |
| `0.1` | notably elevated risk | a balanced setting for most teams |
| `0.01` | above the long tail | you would rather over- than under-react |

Pick one deliberately and keep it stable: a threshold that moves between runs makes two scans
incomparable.

### What it touches, and what it doesn't

- **Only CVE-identified findings.** Enrichment looks for a CVE id in the finding's rule id, so
  it reaches `sca` and `images` results. SAST, secrets and IaC findings carry no CVE and are
  never escalated — their severities come from the scanner and any control floor.
- **Severity, not priority, directly.** Enrichment raises severity; priority is then recomputed
  from severity × exposure × criticality. An escalated CVE on a `restricted`, `supporting`
  component may still not be P1 — which is the point: exploitability matters *in context*.
- **The gate follows automatically.** Because both bands and levels derive from severity,
  `--fail-on-priority` and `--fail-on` see the enriched values with no extra configuration.

### A worked example

A dependency carries a CVE scored CVSS 6.1 → **medium**, on a component classified `public` /
`important`.

| Run | Severity | Priority |
|-----|----------|----------|
| no enrichment | medium | P3 |
| `--epss epss.csv`, score 0.62 ≥ 0.5 | high (one band up) | P2 |
| `--kev kev.json`, and it's listed | critical | P1 |

Same finding, same component, three different answers about when to fix it — and the last is the
one that matters, because somebody is exploiting it today.

**Related:** [EPSS & KEV explained](/learn/epss-and-kev/) ·
[Vulnerability prioritization](/learn/vulnerability-prioritization/) ·
[CVE, CVSS and severity](/learn/cve-cvss-and-severity/) ·
[`scan` flags](../reference/cli.md#draugr-scan-sagayaml--dir)

## The component is part of the finding

A finding records which component it came from, and that is what makes its band checkable. The
band is computed from that component's declared `exposure` and `criticality`, so a report showing
`P1` without naming the component would state a conclusion and withhold its premise.

It also means the same flaw in two components is **two findings**. A library shared by a
public, business-critical service and an internal tool is one vulnerability and two different
risks — and reporting it once would keep whichever was merged first, which can be the one that
does not matter.

## Some findings are not bounded by the component

Exposure and criticality answer "how much does a flaw here matter", and for a dependency CVE that
is exactly the right question: a vulnerable library reachable from the internet is a different
problem from the same library in a batch job.

It is the wrong question for a **leaked credential**. A credential is valid wherever it is valid —
a cloud account, a registry, an artifact store — and git history is frequently readable by more
people than the service is reachable by, so `internal` can understate who is able to obtain it.

So a control may declare that its findings are ranked at a fixed **context tier**, regardless of
what the component says. The `secrets` control declares **C1**, the tier a public, business-critical
component gets — so a credential on the least exposed, least critical component in your descriptor
ranks exactly as it would on your front door.

With the control's severity floor at `high`, that means **P1**. Two reasons it is not something
short of P1:

- `--fail-on-priority P1` is the gate this documentation recommends. Anything lower means a
  credential fails the severity gate and passes the priority one, which is the same contradiction
  one band over.
- The claim is that exposure does not bound the finding. A band that still moves with exposure,
  only less, is a third position — *exposure partly bounds it* — that nothing argues for.

A **tier** rather than a fixed band, because the claim is about exposure and not about urgency.
Severity is still the scanner's answer and the severity floor's: a critical finding and a high one
should not collapse into one row because they share a control.

The report says when the floor applied, because a band you cannot reconstruct from the component's
classification is one you have to take on trust. It states the conclusion rather than the mechanism:
the floor works by ranking the finding at the most exposed tier, but printing that against a
component you have classified as internal reads as a claim about the component, and you can see it
is not true.

```
  P1   high   -   github-pat   secrets   gitleaks   cfg.txt:1
       ↑ a leaked credential is high priority wherever it is found
```

**A false positive is not what this is for.** A finding you have judged belongs in
[`config.exclude`](../reference/saga-schema.md#configexclude), where it stays in the report marked
suppressed with your reason. Ranking it lower would hide it from the gate and record nothing —
the wrong lever, and the same category error this exists to fix.

Nothing else changes. A control that declares no floor is ranked entirely by the matrices above,
which is correct for every control that does not override its scanner's severity in the first
place.
