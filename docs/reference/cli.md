---
title: CLI reference
description: Every Draugr command and flag, from scan and diff to survey, doctor, and tools.
section: Reference
order: 10
---

# CLI reference

All commands accept these **global flags**:

| Flag | Default | Description |
|------|---------|-------------|
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error` |
| `--log-format` | `console` | `console` (human-readable, colorized on a terminal), `json`, or `text` |
| `--log-file` | — | also append every record to this file, at `trace` level and unclamped |
| `--offline` | `false` | make no network calls (also `DRAUGR_OFFLINE=1`) |
| `--config` | — | machine/organisation settings file, used instead of the discovered ones (also `DRAUGR_CONFIG`) |

**`--offline`** says once that this machine has no network, and every place Draugr would reach out
honours it. Optional fetches are skipped with a line saying so; a command whose whole purpose is
to download — `feeds update`, `tools install`, `self-update` — refuses and names what it would
have fetched. A scan runs against whatever each tool already has on disk, and a tool with nothing
on disk reports an error rather than a clean result.

`draugr doctor` lists every network call Draugr can make, so a runner can be prepared from that
list rather than one failure at a time. See
[running air-gapped](../guides/air-gapped.md).

**Seeing what Draugr is doing.** `--log-level debug` narrates the run: what was planned, the
**exact command** handed to each scanner with its working directory, duration and exit code,
cache hits, findings per control, and aggregation.

```console
$ draugr scan . --log-level debug
DEBUG planned job control=sca scanner=trivy-fs target_kind=repository
DEBUG ran scanner tool tool=trivy argv="trivy fs --quiet --scanners vuln --format sarif /tmp/…" duration=43ms
DEBUG scan complete control=sca scanner=trivy-fs findings=0 duration=50ms
```

**When a control fails.** A control whose scanner exits badly is reported as an error rather than
a pass, and the error carries the tool's own first line of output:

```
Controls:
  dast  ERROR  did not run
        nuclei: run nuclei: exit status 1: could not read templates: no such file or directory
```

That one line is usually enough. When it isn't, `--log-level trace` relays everything the
scanner printed, verbatim, along with the exact argv Draugr ran:

```bash
draugr scan . --log-level trace 2>trace.log
```

A relayed stream is printed as a block rather than escaped onto one line, so it reads the way the
tool wrote it:

```console
10:35:10 TRACE  tool stdout tool=trivy
  ┌ stdout
  │ {
  │   "version": "2.1.0",
  │   "runs": [
  …
  └
```

Verbose by design — reach for it when the summarised line hasn't answered the question. Logs go
to stderr, so `2>trace.log` keeps them out of a report on stdout.

**`--log-file` is usually the better way to get it.** The terminal keeps whatever `--log-level`
you asked for; the file gets *everything*, at trace, with no ceiling on how much of a tool's
output is kept:

```bash
draugr scan .                       # nothing on screen but the report
draugr scan . --log-file draugr.log # …and the whole run in a file
```

One `--log-level` cannot serve both. A terminal wants a stream it can read, so a relayed stream
is clamped there and says how much was left out. A file is what you attach to a bug report, where
the answer is disproportionately in the part a terminal had no room for — so it is clamped at
nothing. On the same scan of a findings-rich repository, the terminal shows about 5 KB with a
truncation notice and the file holds 80 KB with none.

The file is **appended**, not truncated, because the second run is usually the one that
reproduces the problem. It is written `0600` and never coloured. A `--log-file` that cannot be
opened **fails the run** rather than being skipped: a log silently not written leaves the run
looking normal and the evidence you asked for missing.

**Reading a dense log.** The `console` format gives each part of a record its own weight, so the
shape of a line is legible before its content: the **message** strongest, because it is what you
scan for; the level coloured; timestamps and attribute keys dimmed; values plain. An `error` or a
non-zero `exit_code` is coloured too — in a few hundred debug lines that is nearly always the one
worth finding.

Colour changes the rendering and never the text, so records stay greppable. `NO_COLOR=1`, a pipe
or a redirect give the same output without the escapes, and `--log-format json` is unaffected by
all of it.

Logs go to **stderr**, so they never pollute a machine-readable report on stdout.

Telemetry (traces/metrics) is opt-in via standard `OTEL_*` environment variables; it is a
no-op when unset.

---

## `draugr init [dir]`

Scaffold a `draugr.saga.yaml` for a project (default: the current directory), detecting the
stack to pre-fill sensible controls — Go adds `gosec` to `sast`, a `Dockerfile` adds an `images`
stub, dependency manifests confirm `sca`. Edit it, then `draugr scan`.

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | `draugr.saga.yaml` | Path to write (`-` for stdout) |
| `-f, --force` | `false` | Overwrite an existing file |

```bash
draugr init                 # write draugr.saga.yaml for the current project
draugr init -o - | less     # preview without writing
draugr init services/payments --fragment    # a Saga fragment, component named for the directory
```

For an instant scan with no file at all, use zero-config `draugr scan .` (below).

## `draugr scan [saga.yaml | dir]`

Load a Saga, run the applicable controls, and produce a pass/fail verdict. Prints a
human-readable **console** summary to stdout by default (`--format` for other formats).
**Exits non-zero when the verdict is `fail`.**

**A descriptor in the directory wins.** Point `scan` at a directory — or omit the argument — and
it uses the descriptor there if one exists. Everything that file declares applies: the controls
chosen, the components, and the exposure and criticality that drive prioritization.

Any of these names counts, which are the ones the editor integration already validates:

```
draugr.saga.yaml    web.saga.yaml    .saga.yaml    api.saga.yml
```

If the descriptor cannot be read, the scan **fails**. It does not fall back to zero-config: the
reason a descriptor was skipped has to be reported, or a broken file produces a green scan.

**More than one descriptor stops the scan.** Two are two different accounts of what the project
is — different components, different controls, different exposure driving different priorities —
so Draugr does not pick. On a terminal it asks which one; anywhere else it lists them and stops,
because a prompt in CI would hang the pipeline. Name the file to skip the question:

```bash
draugr scan ./web.saga.yaml
```

**With more than one component, the report breaks the verdict down by component** — each judged
by the same policy as the run, so the parts cannot disagree with the whole. Components with
nothing against them are listed as passing, and findings from project-wide controls (which belong
to no component) are counted separately.

**A surface with no control enabled is called out.** If a component declares repositories,
images, hosts or infrastructure and nothing is enabled to check them, the scan says so — that
combination reads as a clean pass over something nobody looked at. A note rather than a failure,
since the choice may be deliberate; `--no-tips` or `DRAUGR_NO_TIPS=1` silences it.

When the component declares hosts, the note also says why `dast` is not among the controls it
names: `dast` sends attack traffic at a live service, so it is never suggested on the strength of
a descriptor mentioning a URL. Enable it yourself, having decided.

**Contextual tips.** After a console scan, up to two one-line hints may follow the report. Each
is gated on the run it is about, and none of them affects the verdict:

| Tip | Shown when |
|---|---|
| Priority gating | The run passed, carries P1 or P2 findings, and `--fail-on-priority` is unset |
| Where the report went | `CI` is set in the environment, with no `-o` and no `config.publishers` |
| Risk classification | There are findings and no component sets `exposure` or `criticality` |
| Caching | The run took over a minute and `--cache-dir` is unset |

At most two per run, highest-consequence first — a block of five is one nobody reads. `--no-tips`
or `DRAUGR_NO_TIPS=1` silences them, as it does the surface note.

### While a scan is running

A scan plans one job per repository, image, host and cluster and runs them concurrently, and the
slow ones are the interesting ones — an image being pulled, a benchmark Job waiting for a node. On
a terminal it says what it is doing, on one line that redraws:

```
scanning 3/11 · images/trivy ×2, sca/trivy-fs
```

How many jobs have finished, then what is in flight; several jobs of the same kind collapse into a
count. The line is erased before the report, so nothing of it survives in what you read afterwards.

Drawn **only when stderr is a terminal**. A report on stdout stays parseable when piped, and a CI
log keeps one line per event rather than a frame per update. `--no-tips` and `DRAUGR_NO_TIPS=1`
turn it off along with the tips.

### What the run cost

Under the scanner builds, the run accounts for itself:

```
Ran 11 jobs in 34.5s — 4 from cache, 1 shared with an identical job.
```

Wall-clock, not the sum of the jobs: they run concurrently, and their sum is a number matching
nothing you waited for. **From cache** is what makes [`--cache-dir`](#using-the-cache-in-a-scan) checkable — a second
run being faster is not evidence that the cache did it. **Shared with an identical job** counts
jobs answered by another job's scan in the same run, which is what two components pointing at one
repository produce.

### Scoping a run

`--components` and `--controls` narrow a run without touching the descriptor — for iterating on
one failing component, or debugging one control, without waiting for the rest:

```bash
draugr scan --components app,frontend
draugr scan --controls sca
draugr scan --components app --controls sca --log-level debug
```

They are a **view over one run**, not a decision. `config.controllers` records that a project does
not need `dast`; editing it to debug is how a temporary change gets committed.

**A scoped run still gates**, because answering "is my fix good?" with "no verdict" would send you
back to a full scan and make the flags useless for the loop they exist for. What it never does is
look like an unscoped run:

```
Draugr — FAIL   (multi 1.0.0)   (scope: 1 of 3 components; sca)

Components:
  app       FAIL   P1 9  P2 8  P3 1  sca
  frontend  not scanned  (--components)
  payments  not scanned  (--components)
```

Skipped components are **listed, not omitted** — a component absent from the breakdown renders
identically to one that passed.

The scope travels into the artifacts too, so a consumer that never saw the command can still tell
a partial answer from a whole one. `report.json` gains a `scope` object, and the SARIF carries it
as run provenance. Both are absent on an unscoped run, so their presence is the signal.

**[`draugr diff`](#draugr-diff-basesarif-headsarif) refuses reports of different scope.** Every
finding in the base and absent from the head is reported as *fixed* — correct when both scans
looked at the same things, and confidently wrong when one was scoped. Two runs of the same scope
compare normally.

A name that matches nothing is an **error**, not an empty scan: `--components frontnd` scanning
nothing and passing is the same "we did not look" verdict in miniature. The message lists what the
descriptor actually declares.

These change **what runs**. [`--min-priority`](#what---min-priority-narrows) changes what is
*printed* from a full run — the two read alike and only one of them changes the verdict.

**Zero-config.** A directory with no descriptor is scanned with `sca`, `secrets`, `sast`
and `iac` — no Saga required.
A one-line note is printed to stderr so machine formats on stdout stay clean. A Saga **file**
argument runs exactly as before.

```bash
draugr scan            # zero-config: scan the current repo
draugr scan ./service  # zero-config: scan another repo directory
draugr scan draugr.saga.yaml   # full control from a descriptor
```

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | — | Directory to write `report.json`, `results.sarif`, and any SBOMs |
| `--fail-on` | `error` | Severity that fails the gate: `error`, `warning`, `note` |
| `--working-tree` | `false` | Scan the checkout as it is on disk, uncommitted work included — for iterating on a fix without committing |
| `--no-gate` | `false` | Report the verdict but exit 0 on a fail — for producing a report to compare later, where [`draugr diff`](#draugr-diff-basesarif-headsarif) is the gate |
| `--fail-on-priority` | — | Also fail the gate on any finding at or above this priority (`P1`–`P4`) |
| `--min-priority` | — | List findings at or above this priority band (`P1`–`P4`). Narrows what is **printed**; artifacts and publishers keep the full set — see [below](#what---min-priority-narrows) |
| `--artifact-min-priority` | — | Also narrow the `-o` artifacts to this band, and record the band inside them. The deliberate opposite of `--min-priority`, and safe for the same reason it is declared — see [below](#what---min-priority-narrows) |
| `--allow-effects` | — | Accept scanner effects for this run (`mutate`, `privilege`). `config.allowEffects` is the reviewed equivalent — see [below](#scanners-that-do-more-than-read) |
| `--kev` | — | CISA KEV catalog: a file path, or `cache`/`auto` to read `~/.draugr/feeds`. A CVE on it is escalated to critical. Overrides `config.exploitability.kev` |
| `--epss` | — | FIRST EPSS scores: a file path, or `cache`/`auto` to read `~/.draugr/feeds`. A CVE at/above `--epss-threshold` is bumped one band. Overrides `config.exploitability.epss` |
| `--epss-threshold` | `0.5` | EPSS probability (0–1) that triggers a severity bump. Overrides `config.exploitability.epssThreshold` |
| `--cache-dir` | — | Enable content-hash caching in this directory |
| `--cache-ttl` | `24h` | Cache entry lifetime (`0` = no expiry) |
| `--cache-read-only` | `false` | Read the cache, never write it — for a run whose results should not be trusted by the next one |
| `--cache-require-digest` | `false` | Do not cache an image identified only by a tag |
| `-j, --jobs` | `0` (auto) | Max scan jobs to run in parallel (`0` = one per CPU); reported as `stats.concurrency` |
| `--format` | `console` | **what to print**: `console`, `markdown`, `json`, `sarif`, `vex`, `template` |
| `--template` | — | inline Go `text/template` (with `--format template`) |
| `--template-file` | — | Go `text/template` file (with `--format template`) |
| `--no-publish` | `false` | Skip the Saga's configured publishers (still writes `-o` artifacts and stdout) |
| `--top` | `10` | Console: max findings to list in the ranked table (`0` = all). The heading says whether you are looking at a shortlist or every finding |
| `--no-tips` | `false` | Suppress the console's contextual tips (also `DRAUGR_NO_TIPS`) |
| `--components` | — | Scan only these components; the verdict says what it covered |
| `--controls` | — | Run only these controls; the verdict says what it covered |
| `--allow-scan-errors` | `false` | Treat a control that couldn't run as a warning rather than a failure. By default an incomplete scan fails the run, because an empty report from a scanner that never ran isn't evidence of anything |
| `--compact` | `false` | Strip indentation and rule documentation from `json`/`sarif` output. For a consumer that acts on the report rather than reads it — see [machine-readable output](../guides/reports-and-publishers.md#compact-output-for-tools-and-agents) |

The four `--cache-*` flags also live in [`draugr.config.yaml`](#draugr-config) under `cache:`,
which is usually the better home: a cache directory describes a runner image, not an application,
and every pipeline on that runner wants the same one.

```bash
draugr scan draugr.saga.yaml
draugr scan draugr.saga.yaml -o out/ --fail-on warning
draugr scan draugr.saga.yaml --min-priority P2        # focus on what matters now
draugr scan draugr.saga.yaml --fail-on-priority P1    # also block on P1 findings
draugr scan draugr.saga.yaml --cache-dir .draugr-cache
draugr scan draugr.saga.yaml -j 4                      # cap parallelism (or -j 1 for serial)
draugr scan draugr.saga.yaml --format markdown        # portable report (MR comment, wiki)
draugr scan draugr.saga.yaml --format json | jq .      # machine-readable
draugr scan draugr.saga.yaml -o out/ --report html    # shareable browser report
draugr scan draugr.saga.yaml -o out/ --report junit   # CI test panel
draugr scan draugr.saga.yaml --format template --template '{{.Verdict}}: P1={{.Priorities.P1}}'
```

**Output formats (`--format`).** stdout defaults to a human **console** summary (verdict,
priority/severity counts, "fix first"). `markdown` produces a portable report for MR comments
or wikis; `html` is a self-contained, browser-viewable report you can publish as a build
artifact; `junit` emits JUnit XML so CI systems (GitLab, Jenkins, Azure DevOps…) surface
findings in their test-results panel; `json` and `sarif` are the machine formats; `template`
renders your own Go `text/template` (see [`config.reports`](saga-schema.md#configreports-and-configpublishers)
for the available fields). Regardless of `--format`, `--output <dir>` always writes both
`report.json` and `results.sarif` for CI/code-scanning — plus one SBOM per target when the Saga
sets [`config.sbom`](saga-schema.md#sbom-generation). To render **multiple** formats and deliver
them somewhere in one run, declare
[`config.reports` / `config.publishers`](saga-schema.md#configreports-and-configpublishers) in the Saga.

**Tuning parallelism (`-j`/`--jobs`).** By default Draugr runs up to one scan job per CPU. But
scanners like Trivy and Semgrep are themselves multi-threaded, so on a busy or small machine
that default can oversubscribe the box and *slow the run down* — dial it down with `-j`. On a
big CI runner you can dial it up. `-j 1` runs serially (deterministic output; handy for
debugging). The run's JSON `stats` reports the effective `concurrency` alongside `jobs` (total
jobs), `scans`, `cacheHits`, and `deduped`, so you can see the effect and tune from evidence.

**Two scales, and which one gates.** The console reports **severity bands** (critical / high /
medium / low), derived from a finding's CVSS score where the scanner supplies one. `--fail-on`
takes **SARIF levels** (`error` / `warning` / `note`), which is what scanners emit and what the
gate evaluates. They line up like this:

| Severity band | From CVSS | SARIF level | `--fail-on error` | `--fail-on warning` |
|---------------|-----------|-------------|:-----------------:|:-------------------:|
| critical | 9.0–10.0 | `error` | fails | fails |
| high | 7.0–8.9 | `error` | fails | fails |
| medium | 4.0–6.9 | `warning` | — | fails |
| low | 0.1–3.9 | `note` | — | — |

Typing a band where a level belongs — `--fail-on high` — is **rejected**, with a message saying
which ladder the flag is on. It has to be: an unrecognized level ranks below every finding, so
accepting it would widen the gate to *everything* while reading like a narrowing.

A finding with no CVSS score keeps whatever level its scanner assigned; a control may also apply
a **floor** (a leaked secret is never reported as low, however the scanner scored it). To gate on
business risk instead of raw severity, use `--fail-on-priority` — it accounts for the
component's exposure and criticality, which a bare severity cannot.

**Priority** requires components to declare `exposure`/`criticality` (see the
[Saga reference](saga-schema.md)); Draugr ranks each finding P1–P4 from its severity and
the component's risk. See [concepts](../concepts/prioritization.md).

**Exploitability (`--kev`/`--epss`)** raises a finding's severity by real-world signals — a
CVE on CISA's [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(confirmed exploited) becomes critical; a CVE at/above the [EPSS](https://www.first.org/epss/)
threshold (predicted likely) is bumped one band. Both are optional, offline (bring your own
downloaded file), and only affect findings whose rule id is a CVE.

### Scanners that do more than read

Most scanners read an artifact and nothing else. A few do more, and say so: they declare an
**effect**, which Draugr shows before a scan, enforces during one, and records afterwards.

| Effect | Meaning |
|---|---|
| `network` | Sends traffic to the target rather than reading an artifact |
| `disclosure` | Sends information about the target to a **third party** |
| `mutate` | Creates or changes something that outlives the scan |
| `privilege` | Needs access beyond what reading the target requires |

**`network` and `disclosure` differ in who is affected.** Network traffic asks whether you are
entitled to probe a host. Disclosure asks whether you are content for a vendor to learn what you
just told them — a hostname, a dependency manifest, a repository's source. Those are not the same
decision, so what is actually sent appears in the effect's detail line, and every scanner that
discloses documents it under *What is sent* in its colocated doc.

Run `draugr controls` to see which scanners declare what.

**`mutate` and `privilege` do not run until accepted.** Changing a target, or asking for elevated
access, is a decision someone should make on purpose:

```yaml
config:
  allowEffects: [mutate]
```

or `--allow-effects mutate` for a single run. A scanner whose effect has not been accepted stops
the run *before* it does anything, and the refusal says what it would have done.

**`network` is declared, not gated.** A dynamic scanner exists to send traffic; requiring consent
per run for the thing the control is *for* teaches people to accept without reading. It is stated
and recorded instead — and the obligation it carries, that you are entitled to probe the host, is
in the [scope and disclaimer](../trust-and-operations/disclaimer.md).

What a run actually did appears in the report, so evidence describes what happened rather than
what was configured. Only scans that really executed count: a cache hit means the traffic was not
sent this time.

### Which build of each scanner ran

A scan runs whatever is on `PATH`. That is deliberate — an operator may have an experimental
build, a fork, or a distribution package with a vendor suffix, and refusing them would be Draugr
mistaking *"I cannot verify this"* for *"this is wrong"*.

But a report that cannot say which build produced its findings cannot be reproduced, so it says:

```
Scanners: gitleaks 8.30.1, trivy 0.69.3
Scanners: gitleaks 8.30.1, semgrep 1.173.0, trivy 0.69.3
```

The first line lists the builds Draugr fetched **and checked**: each sits in `~/.draugr/bin`, the
install record has it, and the file still hashes to what was recorded. The hash is what makes that
a claim about a file rather than about a path.

The version is on both lines, and on the second it is the whole point. A tool Draugr installed can
be identified from its install record; one you brought cannot, so Draugr asks it — which is what
lets the report name the build behind a finding rather than only disclaiming responsibility for
it. A tool that will not say gets no version, and that too is recorded rather than guessed.

Everything else gets its own line with the reason, because that is the one you have to decide
about. What Draugr can say about a binary has five levels:

| Level | What it means |
|---|---|
| `pinned` | Installed at the version Draugr ships, matching a checksum recorded in this build |
| `signed` | Installed at another version, matching checksums signed by the upstream's Sigstore identity |
| `checksum` | Installed, matching an unsigned checksums file fetched from the upstream |
| `unverified` | Installed, with nothing published to check it against |
| `external` | Not installed by Draugr — found on `PATH` |

`checksum` is kept distinct from `unverified` deliberately: an unsigned checksums file over HTTPS
proves the download was not corrupted or truncated, without proving the upstream published it.
That is weaker than a signature and much stronger than nothing.

None of this affects the verdict — it is a fact about the run, not a finding about your software.

### `--format` prints; `--report` writes

Two different questions, which is why they are two flags.

**`--format` is what appears on screen.** It accepts only formats a person or a pipe can sensibly
receive: `console`, `markdown`, `json`, `sarif`, `vex`, `template`. `--format html` is rejected —

```
draugr: html is a document, not something to print: use `--report html` with `-o <dir>`
```

An HTML report is a styled document with its CSS inlined; a JUnit file is read by a CI runner from
a path, never by a person. Printing either because a plausible-looking flag was typed is not
behaviour worth defending, so neither is offered here.

### `--working-tree`, for the loop of fixing something

A scan reads the committed revision, so the loop of fixing a finding — edit, scan, check — needs a
commit per iteration. `--working-tree` reads the checkout as it is instead:

```bash
draugr scan draugr.saga.yaml --working-tree
```

```
Scanned: . working tree at 3f9a1c2b+ (7 uncommitted files, not reproducible)
```

The `+` is git's own convention for a tree that has moved past its commit, and **not
reproducible** is the point: nobody else can check out what you just scanned, so the report says
so rather than implying a revision it does not describe. For the same reason these scans are
**never cached** — two runs at one revision read different bytes, and a cache keyed on the
revision would answer the second with the first's findings.

It reads a **copy**, not your checkout. Scanners cannot write into your files, and `paths` /
`ignore` scoping prunes the copy — against a real checkout, pruning would be deleting your work.
The file list is `git ls-files -co --exclude-standard`: tracked files plus untracked ones that are
not ignored, so a `node_modules` or a local `.env` is left out for the same reason a commit would
leave it out.

A remote repository is **refused**, naming it. There is no working tree to read, and falling back
to the committed revision would answer a different question while looking like it answered this
one.

**`--report` is what gets written**, into the directory `-o` names:

```bash
draugr scan draugr.saga.yaml -o out/                          # report.json + results.sarif
draugr scan draugr.saga.yaml -o out/ --report html,junit      # report.html + report.junit.xml
draugr scan draugr.saga.yaml -o out/ --report vex             # openvex.json
draugr scan draugr.saga.yaml -o out/ --report html --format console
draugr scan draugr.saga.yaml -o out/ --report gitlab-codequality
```

The GitLab formats — `gitlab-sast`, `gitlab-secret-detection`, `gitlab-codequality` — are
`--report` only, for the same reason `junit` is: a GitLab runner reads them from a path named in
`artifacts: reports:`, and nobody reads one. See
[reports & publishers](../guides/reports-and-publishers.md#gitlabs-own-report-formats) for which GitLab surface each
one feeds, and on which tier.

`-o` on its own still writes `report.json` and `results.sarif`, which is what pipelines already
depend on. `--report` replaces that default rather than adding to it, so what you ask for is what
you get.

This mirrors the descriptor, which has always kept the two apart:
[`config.reports`](saga-schema.md#configreports-and-configpublishers) is *what to render* and
`config.publishers` is *where to send it*.

### What `--min-priority` narrows

`--min-priority` decides what a **run shows you**. It never decides what a run **records**:

| Output | Narrowed by `--min-priority`? |
|---|---|
| Console, markdown, HTML, JUnit | **Yes** — with a note saying how many were hidden |
| `--format json` / `--format sarif` on **stdout** | **Yes** |
| `-o <dir>/report.json` | Its **findings list** only. The priority counts always describe the whole run, so you can still see the backlog you chose not to read |
| `-o <dir>/results.sarif` | **No** — always complete |
| Configured publishers, including `github` code scanning | **No** — always complete, and the run logs that it ignored the flag |

The split exists because of one asymmetry: **GitHub code scanning resolves any alert missing
from an upload as fixed.** A filtered report published there would quietly close real findings,
in the one place the filtering is invisible.

#### Narrowing on purpose

That asymmetry is an argument against narrowing a file *by accident*, which is what
`--min-priority` would be doing. Narrowing one on purpose is a different act, and there are two
ways to say it:

- **`--artifact-min-priority P1`**, or **`minPriority: P1`** on a report in
  [`config.reports`](saga-schema.md#configreports-and-configpublishers) — narrows the written
  SARIF and JSON.
- **`draugr diff --format sarif`** — emits only the findings a change introduced, which is the
  version of this a pull request actually wants.

Both **record what they left out**: a narrowed SARIF carries a `draugr/min-priority` provenance
entry naming the band, exactly as a scoped run records its scope. That is what keeps the
consequence visible rather than surprising — an alert closing because you asked for P1 only is a
decision; one closing because a flag leaked into a file is a bug.

The alert lifecycle still applies, and it is worth saying precisely: an upload narrowed to `P1`
resolves the P2–P4 alerts **for the ref and category it was uploaded against**. A pull-request run
uploads against the pull request's own ref, so it never touches your default branch's alerts —
which is what makes narrowing safe there, and why a push, which does upload against the default
branch, is never narrowed. The same reasoning protects `results.sarif`: it
feeds [`draugr diff`](#draugr-diff-basesarif-headsarif) and the
[GitHub Action's](../guides/github-action.md) SARIF upload, and a baseline missing findings makes
the next scan's delta wrong.

So the flag is for reading — a terminal, or an agent asking for the short list. On `draugr-demo`,
`--format sarif --compact --min-priority p1` is 61% smaller than the full report (11.7 KB against
30.1 KB) because the rules the omitted findings referenced leave with them.

---

## `draugr diff <base.sarif> <head.sarif>`

Compare two scans and classify every finding as **new**, **fixed**, or **unchanged** — the
security delta of a change, typically a PR's head vs its base branch. Inputs are the
`results.sarif` files that [`draugr scan -o`](#draugr-scan-sagayaml--dir) writes, which are always
complete regardless of `--min-priority`.

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `console` | output format: `console`, `json`, `markdown`, `sarif`. `sarif` emits the **new** findings only, for code scanning on a pull request |
| `--min-priority` | — | report only **new** findings at or above this priority band (`P1`–`P4`); fixed and unchanged are unaffected. Narrows the diff, never the scans it was computed from |
| `--repository` | — | keep only **new** findings from this repository, plus those belonging to none (an image, a host). For a code-scanning upload, whose paths anchor to one checkout |
| `--fail-on-new` | — | fail if a **new** finding is at or above this severity: `error`, `warning`, `note` |
| `--fail-on-new-priority` | — | fail if a **new** finding is at or above this priority (`P1`–`P4`) |
| `--publish` | `false` | post the diff as a sticky pull-request comment. Picks `github-pr-comment`, `azure-pr-comment` or `gitlab-mr-comment` from the CI environment; no-ops off a PR |

```bash
draugr diff base/results.sarif head/results.sarif                     # console delta
draugr diff base/results.sarif head/results.sarif --format markdown   # MR comment
draugr diff base/results.sarif head/results.sarif --fail-on-new-priority P1
draugr diff base/results.sarif head/results.sarif --publish           # sticky PR comment (in CI)
```

**Differential gating.** `--fail-on-new` / `--fail-on-new-priority` fail a PR only for findings
it *introduces*, not the pre-existing backlog — so a gate stays adoptable where a whole-backlog
gate would block every PR. The command exits non-zero when the gate trips. A typical CI setup
scans `main` on push and stores `results.sarif` as an artifact, scans the PR, then diffs the two.

**Both sides are committed revisions.** A repository is cloned before it is scanned, whether it
was given as a URL or a local path, so each SARIF file describes a commit rather than a working
tree. In CI that is the intent. Locally it means scanning, editing and re-scanning produces two
identical files and an empty diff — commit between the two scans, or point `revision` at each
revision in turn. See
[URLs and paths](saga-schema.md#where-a-repository-comes-from-urls-and-paths).

**Finding identity.** Findings are matched on `(tool, rule, file, message)` — deliberately
ignoring the line number (which drifts as code moves) and the severity level (a re-scored finding
is still the same issue), so genuinely-carried-over findings aren't reported as fixed + new.

---

## `draugr survey`

Discover what an application is made of and write it into a Saga descriptor.

**Each surveyor is its own subcommand**, so a surveyor's options sit with the surveyor they
belong to:

| Command | Discovers | Options |
|---|---|---|
| `draugr survey k8s images` | unique container images running in a cluster, with their digests | `--namespace`, `--no-exposure` |
| `draugr survey k8s cluster` | the cluster itself, as an `infrastructure` component | `--namespace` |
| `draugr survey github repos` | repositories in a GitHub organization | `--org` |
| `draugr survey gitlab projects` | projects in a GitLab group, subgroups included | `--group` |
| `draugr survey azure repos` | Git repositories in an Azure DevOps organization or project | `--org`, `--project` |

Shared by all of them: `-o, --output` (default stdout), `--replace`, `--fragment`, `--name`,
`--version`. The `k8s` group also takes `--context`, which selects the cluster for both of its
surveyors.

### Writing a fragment instead of a descriptor

`--fragment` writes a [Saga fragment](../guides/saga-fragments.md) — components and nothing else —
for a descriptor to include:

```bash
draugr survey k8s images --namespace team-a --fragment -o team-a.saga-fragment.yaml
```

A fragment is part of a descriptor rather than a thing to release, so it carries no `release:`, and
`--name` and `--version` are refused alongside it. It enables no controls either: `config` in a
fragment cannot express them, and the descriptor that includes it decides what to run. That is the
point of the option — a team owns a namespace and hands its surface to a descriptor somebody else
maintains.

The output name matters. `draugr validate` and a `fragments:` reference both decide what a file is
from its suffix, so `--fragment` requires `-o` to end in `.saga-fragment.yaml` (or `.yml`) and says
so before it connects to anything.

### Not proposing an exposure

`--no-exposure` leaves `exposure` unset rather than guessing it from cluster topology:

```bash
draugr survey k8s images --no-exposure -o draugr.saga.yaml
```

The lookups are skipped rather than made and discarded — they need permissions a namespace-scoped
credential may not have, and spending them to produce warnings about a value nobody asked for helps
no one. Use it when `draugr classify` is where exposure gets decided, or when the credential cannot
read Ingresses, Services and NetworkPolicies.

Auth: each forge surveyor reads a token from the environment (or from scope config); the Kubernetes
surveyors use your ambient kubeconfig (`KUBECONFIG` / `~/.kube/config` / in-cluster).

**Without a token, every forge answers with the public repositories only** — the survey warns,
because the descriptor that results looks complete and is missing every private one.

| Forge | Token | Self-hosted instance |
|---|---|---|
| GitHub | `GITHUB_TOKEN` | `GITHUB_API_URL`, including the `/api/v3` path Enterprise Server serves under — the same variable the publisher reads, and one Actions already sets on a GHES runner |
| GitLab | `GITLAB_TOKEN` | `GITLAB_URL`, or the `CI_API_V4_URL` a runner already sets |
| Azure DevOps | `AZURE_DEVOPS_EXT_PAT`, else `AZURE_DEVOPS_TOKEN` — needs the **Code (read)** scope | `AZURE_DEVOPS_URL`, including its collection |

```bash
draugr survey github repos --org my-org -o draugr.saga.yaml
draugr survey gitlab projects --group my-group -o draugr.saga.yaml
draugr survey azure repos --org my-org -o draugr.saga.yaml
draugr survey k8s images --namespace prod -o draugr.saga.yaml
```

**`draugr survey azure repos` takes `--project` or leaves it out**, and the two answer different
questions: one project is a team's surface, the whole organization is the estate. Azure DevOps
makes the project optional for that reason, so Draugr passes the choice through.

```bash
draugr survey azure repos --org my-org --project Platform -o draugr.saga.yaml
```

**`--namespace` may be repeated, and each one becomes its own component** with its own proposed
exposure:

```bash
draugr survey k8s images --namespace payments --namespace checkout -o draugr.saga.yaml
draugr survey k8s images --namespace payments,checkout -o draugr.saga.yaml   # equivalent
```

Naming no namespace describes every namespace the same way — a component each, with its own
images and its own proposed exposure. `--namespace` narrows *which* namespaces are described, not
whether they are kept apart: a namespace is what a team owns, so it is what a finding has to be
attributed to, and exposure is a property of one namespace's topology rather than a cluster's.

On a large cluster that is a lot of components — a managed cluster with two hundred namespaces
produces two hundred. Name the ones you own.

**It says what it wrote.** A survey that writes a file reports the path and what is now in it, on
stderr so a descriptor sent to stdout stays a descriptor:

```
wrote draugr.saga.yaml — 12 components, 12 repositories
```

A run that added to an existing descriptor says what it contributed, and a survey that
discovered nothing says so — a descriptor describing nothing is almost always a scope or
credentials problem, and the count alone would read as success.

**The output is scannable as written.** Discovery enables the controls the surface it found can
be checked with — repositories imply `sca`, `secrets`, `sast` and `iac`; images imply `images`;
hosts imply `headers` and `tls`; infrastructure implies `infrastructure`. A descriptor that
describes an application but enables nothing would report `PASS` on its first scan having checked
nothing, which is not what "the descriptor writes itself" should mean.

`dast` is deliberately never enabled this way: the other host controls read a response, while
`dast` sends attack traffic at a live service, and that is not a decision discovery makes on your
behalf.

**A control you have already configured is never touched** — including one set to
`enabled: false`. A survey runs against a descriptor people edit, and one that switched
something back on would be worse than the problem it solves.

**Run several against one descriptor** — each survey folds into the Saga already at `--output`,
which is also how discovery is added to a descriptor you maintain by hand.

When scoped to a specific namespace, `k8s images` also **proposes each component's `exposure`**
from topology (Ingress/external Service → `public`, NetworkPolicy → `restricted`, else
`internal`). Each proposal is named on the way out, with the value chosen, because in the file it
is indistinguishable from a decision:

```
exposure proposed from cluster topology, not confirmed — run `draugr classify` to set it:
  payments  public
```

A component that already carries an exposure keeps it and is not listed. Confirm the rest, and set
`criticality`, with [`draugr classify`](#draugr-classify-sagayaml--directory).

### Why subcommands

The previous `--k8s-images` / `--k8s-namespace` / `--github-org` flags were related to each other
in ways nothing expressed. `--k8s-namespace` meant something only alongside `--k8s-images`, so

```bash
draugr survey --github-org acme --k8s-namespace prod   # namespace applied to nothing
```

was accepted in silence. Each surveyor's options now live on its own command, where an option
that does not belong is rejected rather than ignored. The old flat flags — `--k8s-images`,
`--k8s-namespace`, `--github-org` — are no longer accepted; use the subcommands above.

---

## `draugr classify [saga.yaml | directory]`

A guided wizard that sets each component's **`exposure`** and **`criticality`** — the two
inputs to finding prioritization — and writes them back into the Saga (preserving comments and
formatting). It asks a few questions per component and derives the labels; by default it only
asks about unclassified components.

Finds the descriptor the same way [`draugr scan`](#draugr-scan-sagayaml--dir) does: with no
argument, or with a directory, it uses the `*.saga.yaml` there. A directory holding more than one
is an error naming them, and one holding none says so — unlike a scan, there is nothing to
synthesize, because exposure and criticality are judgements that have to be recorded somewhere.

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Re-classify every component, not just unclassified ones |
| `--components` | *(all)* | Only these components, by name. Naming one re-asks about it even if it is already classified |

A name that matches no component is an error listing the ones that exist — a silent skip would
report "all components are already classified", which answers a question nobody asked.

```bash
draugr classify                              # the descriptor in this directory
draugr classify draugr.saga.yaml             # a specific file
draugr classify --components gateway,api     # redo two, leave the rest alone
```

---

## `draugr validate [saga.yaml | glob ...]`

Parse each Saga, resolve `${{ VAR }}` references, and check it against the schema — without
running any scanners. Fast and dependency-free, so it suits a pre-commit hook, a CI lint step, or
an editor. **Exits non-zero if any file is invalid.**

Accepts paths and globs, and with no arguments discovers every `*.saga.yaml` and
`*.saga-fragment.yaml` (and their `.yml` forms) beneath the current directory — useful in a repo
holding one Saga per service. `.git`, `node_modules`, `vendor` and `dist` are skipped.

**A fragment is checked as a fragment.** Held to a Saga's rules it would fail on a missing
`release:`, which every valid fragment lacks — and one that only validates after merging is one
nobody can check before merging it.

```bash
draugr validate                          # every Saga in the repo
draugr validate draugr.saga.yaml         # one file
draugr validate 'services/*/*.saga.yaml' # a glob (quote it, so the shell doesn't expand it first)
draugr validate azure.saga.yaml --resolved  # print the descriptor with every fragment merged
```

Each file is reported on its own line, so one failure doesn't hide the rest:

```
✓ draugr.saga.yaml is valid
✗ svc-b/web.saga.yaml
    unknown field "componnets" in the top level — check the spelling, or see …
```

A pattern that matches nothing is an error rather than a silent success — otherwise a typo'd
pattern would make a CI lint step quietly pass.

### `--resolved`

Print the descriptor with every [fragment](../guides/saga-fragments.md) merged in, each source
named. Once a descriptor is assembled from several files, opening one of them no longer tells you
what is in force.

```bash
draugr validate azure.saga.yaml --resolved
```

```yaml
# Resolved Saga — every fragment merged. Generated by `draugr validate --resolved`.
# Valid input: comments are the provenance, so this can be scanned as it stands.
#
# root:     azure.saga.yaml
# fragment: services/payments/draugr.saga-fragment.yaml
# fragment: https://github.com/acme/platform.git@v2.4.0 (40d23df24acc) components/api/draugr.saga-fragment.yaml
```

Provenance is carried in comments, so the output is **also a valid descriptor** — which is what
makes it worth piping:

- **Flatten it to cross an air gap.** Resolve where there is network, scan the result where there
  is none. See [running air-gapped](../guides/air-gapped.md).
- **Pin it.** Each remote fragment is recorded at the commit it resolved to, so a flattened copy
  behaves as a lockfile.
- **Diff it in CI.** Commit the resolved descriptor and fail when it stops matching, so a one-line
  `fragments:` change is reviewed by its effect rather than its cause.
- **Query it.** `draugr validate azure.saga.yaml --resolved | yq '.components[].name'`

The spent `fragments:` block is dropped from the output: everything it named is already merged in,
and leaving it would make the flattened copy resolve again on the next scan.

Takes one descriptor at a time, because the output is itself a descriptor and several
concatenated would not be.


## `draugr doctor [saga.yaml]`

Preflight the environment: report which external scanner tools are **present, missing, or of
what version**, with an install hint for each — so a missing tool is caught up front instead
of failing mid-scan. Given a Saga, it first **validates the descriptor**, then checks only the
tools its enabled controls need (`trivy`, `gitleaks`, `semgrep`, plus `git` for repo scans, and
`gosec` only when a component opts into it). **Exits non-zero when the descriptor is invalid or a
required tool is missing**, so it gates CI: `draugr doctor saga.yaml && draugr scan saga.yaml`.

**Without a Saga it is an inventory, not a verdict.** It lists every tool Draugr can use and
which are present, and exits zero — nothing has been selected, so nothing is required. Several
entries are alternatives nobody needs by default: the `infrastructure` control's default scanner
reads the Kubernetes API directly and needs no binary, so `kube-bench` being absent is not a
problem to solve. Pass a descriptor to ask the question that has an answer.

A tool is also reported as unusable when it is installed but its supporting data is not —
`kube-bench` without its `cfg/` benchmarks, `nuclei` without its templates. Being on PATH is not
the same as being able to run.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit the report as JSON instead of a table |
| `--offline` | `false` | Skip the check for a newer draugr release (also `DRAUGR_NO_UPDATE_CHECK=1`) |

```bash
draugr doctor                       # inventory: what Draugr can use, and what you have
draugr doctor draugr.saga.yaml      # check only what this Saga needs (+ validate it)
draugr doctor --json draugr.saga.yaml
draugr doctor --offline             # no network: skip the update check
```

Doctor also reports the running Draugr version and, best-effort (unless `--offline` /
`DRAUGR_NO_UPDATE_CHECK`), whether a newer release is available — nudging
[`draugr self-update`](#draugr-self-update). The check has a short timeout and never blocks or
fails the command. Provisioning missing scanner tools (pinned + verified) is handled by
[`draugr tools install`](#draugr-tools-install-tool); doctor only reports and hints — it
never downloads anything.

---

## `draugr tools`

Provision and inspect the external scanners Draugr runs. Installs are **opt-in and
checksum-verified** — nothing is ever downloaded during a scan.

### `draugr tools install [tool...]`

Download **pinned** tool binaries, verify each against a **SHA-256 recorded in Draugr**
(sourced from the upstream checksums files), and install them into `~/.draugr/bin` — which
Draugr **adds to `PATH` automatically**, so `scan`/`doctor` use them with no shell config. With
no arguments, installs everything Draugr can provision (`trivy`, `gitleaks`, `gosec`, `cosign`).

| Flag | Default | Description |
|------|---------|-------------|
| `-y, --yes` | — | Skip the confirmation prompt |
| `--dry-run` | — | Print the install plan and exit |
| `--force` | `false` | Reinstall even when the pinned build is already present |
| `--version` | — | Install this version instead of the one Draugr ships (one tool at a time) |
| `--saga` | — | Install only the tools that descriptor's scan will run |

```bash
draugr tools install            # plan → confirm → install everything, into ~/.draugr/bin
draugr tools install trivy      # just one
draugr tools install --dry-run  # preview the plan, change nothing
draugr tools install -y         # non-interactive
draugr tools install --saga draugr.saga.yaml   # only what this project's scan runs
draugr tools install trivy --version 0.68.0    # a version other than the one Draugr ships
```

**Pinning a version.** A team wanting every pipeline to scan with the same Trivy writes it once,
where it gets reviewed:

```yaml
# draugr.config.yaml
tools:
  trivy:    { version: "0.69.3" }
  gitleaks: { version: "8.30.1" }
```

`--version` overrides that for a single invocation, and takes one tool because it takes one value.

Draugr **does not refuse a version it cannot vouch for.** Someone asking for one has a reason
Draugr does not know about — a fork, a release candidate, a build newer than this release — and
refusing would be blocking them over a gap in Draugr's knowledge. It installs what was asked for
and records how well it could check it, and that record travels into every report the tool goes on
to produce.

What it does refuse is a **contradiction**: a checksum the upstream published that the download
does not match. Nothing published is *unknown*; a published checksum that disagrees says the
download was corrupted or substituted, and installing past that would be ignoring evidence rather
than lacking it.

The install plan says which of these you are getting before anything is downloaded — the `Verify`
column reads `sha256`, `sha256 + cosign`, `upstream cosign`, `upstream sha256` or `unverified`.

**`--saga` installs what a descriptor needs**, resolved the same way
[`draugr doctor`](#draugr-doctor-sagayaml) decides what to check: the enabled controls, and the
scanners those controls will actually select. The two cannot disagree, because they share the
resolution.

On a security tool the smaller set is the defensible one — every binary on `PATH` is one more
thing to trust, keep patched and explain. Where a descriptor needs something Draugr cannot
provision (`kubectl`, `git`) the plan **names it** rather than installing the
rest and reporting success.

The descriptor is not inferred from the working directory, even though `scan` does so. A CI job
running `tools install -y` in a repo that happens to contain one would suddenly provision less,
and may then be handed a different Saga to scan; installing less than before, silently, surfaces
as a mystery failure elsewhere. Instead, when a descriptor is sitting there, the plan says so:

```
Note: `--saga draugr.saga.yaml` would install 2 of these 6 tools — the ones that
descriptor's scan runs.
```

**Already-installed tools are skipped.** Re-running is cheap: a tool already present at the
pinned build is left alone instead of being downloaded and verified again — which matters in CI,
where provisioning runs on every job. The plan names them; afterwards they are counted, so the
output describes what changed:

```
✓ syft 1.49.0 → ~/.draugr/bin/syft (sha256 verified)
7 tools unchanged.
```

"Already present" means the exact bytes Draugr installed: it compares the binary's checksum
against what it recorded, so a **modified binary is replaced**, not accepted — and a replacement
gets its own line. A changed pin also reinstalls. Use `--force` to reinstall unconditionally.

**Plan + confirmation.** It first prints the plan (tool, version, **category**, verification,
destination). When run **interactively** it asks for confirmation; **non-interactively** (CI,
pipes) it proceeds — pass `-y` to be explicit or `--dry-run` to only preview.

**Why cosign is in the toolbox.** cosign is a utility Draugr *uses* to verify the provenance of
other tools (and its own releases, via `self-update`) — but users often don't have it installed,
so signature verification silently falls back to SHA-256-only. Making cosign installable
(`draugr tools install cosign`) closes that loop: install it once and signature verification
"just works" everywhere. It's a **utility** (not a scanner for a control), pinned by SHA-256
(using cosign to verify itself would be circular), and it's **optional** — `doctor` reports it
but never fails because it's absent.

**Provenance.** The SHA-256 pin is the mandatory integrity floor. On top of it, for upstreams
that publish a keyless **cosign** signature over their checksums file (e.g. Trivy), Draugr also
verifies that signature — checking the signing certificate identity and OIDC issuer, then
confirming the archive is listed in the signed checksums — when the `cosign` CLI is installed.
Without `cosign`, or for tools the upstream doesn't sign (e.g. gitleaks), it degrades to
SHA-256-only and says so. Each line reports what was verified (`sha256 + cosign verified` /
`sha256 verified`). If `cosign` is present but verification fails, the install aborts.

Semgrep publishes no release binary, so it is installed from PyPI into a virtual environment
Draugr owns (`~/.draugr/venv/semgrep`), with every artifact in the resolved tree matched against a
digest recorded in this build — dependencies included. It needs **Python 3.10 or newer**; `doctor`
says so when it is missing. `git` is expected from your system.

### `draugr tools list`

Show every tool Draugr knows about: its **category** (scanner/utility), the **controls** it
backs, its pinned version, how it's obtained (managed install / system), and whether
it's currently found (with path + version).

```bash
draugr tools list
```

---

## `draugr feeds`

Fetch and inspect the exploitability datasets that raise a finding's severity by real-world
signals. Fetching is explicit: a scan reads the cache and never reaches the network on its own,
so a gated run stays reproducible and works on an air-gapped runner.

### `draugr feeds update [kev|epss]`

Download CISA's KEV catalog and FIRST's EPSS scores into `~/.draugr/feeds`. With no arguments,
fetches both. A copy less than a day old is left alone unless `--force` is given.

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | `false` | fetch even if the cached copy is current |

```bash
draugr feeds update            # both
draugr feeds update epss       # just the daily one
draugr feeds update --force    # refetch regardless of age
```

EPSS is published gzipped and is decompressed on the way in, so the cache holds a CSV the
scanner can read directly. Each write is atomic — an interrupted fetch cannot leave half a
catalogue behind for the next scan to read as though it were complete.

**In CI, run this as its own step.** A feed outage then fails where it happened rather than
producing a scan that ranked everything as though nothing were exploited.

### `draugr feeds status`

What is cached, how old it is, where it came from, and the digest of each copy.

```
FEED   FETCHED                AGE            SIZE       DIGEST
kev    2026-08-01 09:12Z      6 hours        1.5 MiB    sha256:15b44d7c9c57
epss   2026-07-29 08:55Z      3 days (stale) 10.3 MiB   sha256:41c20e9dc3cf
```

Age is the column that matters: EPSS is republished daily, so a stale copy does not fail — it
ranks a finding lower than today's data would. A scan reading one warns and names the age.

### Using the cache in a scan

Set it once in the descriptor under
[`config.exploitability`](saga-schema.md#configexploitability), or pass it per run. `--kev` and
`--epss` accept a path, or one of two keywords:

| Value | Behaviour |
|-------|-----------|
| a path | read that file; never touches the cache or the network — the air-gapped route |
| `cache` | read `~/.draugr/feeds`; **never** fetches. Errors if nothing is cached |
| `auto` | read the cache, fetching when it is missing or over a day old |

With `auto`, a failed fetch falls back to a cached copy and says so — a feed outage should not
break a gate that has a usable answer on disk. With nothing cached, it is an error.

`DRAUGR_OFFLINE=1` stops `auto` fetching: it reads the cache, or says clearly there is nothing
to read.

**A flag overrides the descriptor only when you type it.** `--epss-threshold 0.5` beats a
descriptor saying `0.1`, even though 0.5 is also the flag's default; leaving it off leaves the
descriptor's value alone.

See [prioritization](../concepts/prioritization.md#exploitability-kev-and-epss) for what the
signals mean and how to choose a threshold.

---

## `draugr config`

Machine and organisation settings, kept apart from the Saga.

A Saga describes an application: its repositories, how exposed a component is, which controls must
pass. Those are facts about the software and belong in its repository. **Which build of a scanner
runs, and what a control defaults to, are facts about a machine or an organisation** — they want
to be the same everywhere, which is exactly why they do not belong in a per-application
descriptor. A descriptor that could pin its own scanner version is one that could downgrade a
scanner until a finding disappears.

```yaml
# draugr.config.yaml
cache:                  # where results are reused between runs, and for how long
  dir: /var/cache/draugr
  ttl: 24h
tools:                  # which build `draugr tools install` fetches
  trivy: { version: "0.69.3" }
controllers:            # merged *underneath* the Saga, so a project overrides only what it names
  sast:
    semgrep:
      config: p/owasp-top-ten
```

`cache.*` mirrors the `--cache-*` flags, and a flag you type always wins — including
`--cache-ttl 0` for no expiry, which is a deliberate instruction rather than an absent one. A
cache directory is a fact about a runner, not about an application, which is why it belongs here
and not in a Saga: one project on two runners should not carry a path that exists on only one of
them. See [caching & performance](../guides/caching-and-performance.md).

`tools.<name>.version` is what [`tools install`](#draugr-tools-install-tool) provisions — so every
runner that shares the config scans with the same build, and two runners cannot produce different
findings from identical code.

### Where it comes from

| | |
|---|---|
| `--config <path>` or `DRAUGR_CONFIG` | that file **alone** — explicit means explicit |
| `./draugr.config.yaml` | this project |
| `~/.draugr/config.yaml` | this machine |

Discovered files are layered, project over home. An explicit one replaces both: a runner image
that names a config expects that config, not that one laid over whatever is in the working
directory.

For behaviour, the full order is **component → Saga → config → built-in**, deep-merged, so an
override replaces only the keys it names.

### Commands

| | |
|---|---|
| `draugr config show` | what is in effect, and **which file each value came from** |
| `draugr config get <key>` | one resolved value |
| `draugr config set <key> <value>` | write a value; `--global` for `~/.draugr/config.yaml` |
| `draugr config unset <key>` | remove one, pruning anything it empties |
| `draugr config init` | a commented starter; `--force` resets a broken file |
| `draugr config validate` | check the files load |

```
$ draugr config show
Files, least specific first:
  ~/.draugr/config.yaml
  /repo/draugr.config.yaml

In effect:
  Setting                          Value            From
  controllers.sast.semgrep.config  p/owasp-top-ten  /repo/draugr.config.yaml
  tools.trivy.version              0.69.3           ~/.draugr/config.yaml
```

`show` is the one worth knowing about. A layered configuration is undebuggable without it —
*"why is Trivy 0.68?"* has one useful answer, and it is a filename.

### If the file breaks

**Draugr refuses to run rather than falling back.** A broken Saga must fail because nobody else
knows what your application is; a broken *config* looks like it has a safe fallback, but taking it
silently is how a pinned toolchain becomes a different one. Somebody pinned that version for a
reason.

Recovery is one command:

```bash
draugr config validate          # what is wrong, and where
draugr config init --force      # start again from the built-in defaults
```

`set` and `unset` cannot break a file: they edit the document rather than rewriting it — **so
comments survive** — and parse the result before saving, so nothing is written that Draugr would
then refuse. Draugr will not silently repair a file it cannot parse, because rewriting somebody's
settings on a guess is worse than refusing them.

### What does not go here

Secrets. Use `${{ ENV_VAR }}` as a Saga does, so the file stays safe to commit.

---

## `draugr controls`

List the security controls Draugr can run — what each checks, its scope, and which scanner(s)
implement it (default, plus any opt-in alternatives marked `*`). The companion to
`tools list`: `controls` maps **control → scanners** ("what runs this check"), while `tools
list` maps **tool → controls** ("why this tool matters").

```bash
draugr controls
draugr controls --options          # also: what each scanner accepts in its Saga block
draugr controls sast --options     # just one control
```

| Flag | Default | What it does |
|---|---|---|
| `[control]` | — | Narrow everything below to one control. A name that is not a control says so and lists the ones that are. |
| `--options` | off | List the Saga options each scanner accepts, read from the schemas the gate enforces. A scanner shown with no options is configured by choosing it — anything else under its block is an error, not a setting that quietly does nothing. |

Enable a control in your Saga under `config.controllers.<name>` (or per component). A control's
scanners are configured under their own keys — `controllers.<name>.<scanner>` — each with an
optional `enabled` flag plus that scanner's options (e.g. `sast: { gosec: { enabled: true } }`).
See [per-scanner config](saga-schema.md#per-scanner-config).

---

## `draugr mcp`

Serve Draugr to AI coding assistants over the
[Model Context Protocol](https://modelcontextprotocol.io), on stdin/stdout.

```bash
draugr mcp                 # read-only tools
draugr mcp --scan=ask      # additionally expose scan, approving each call — the prompt names
                           # the controls, the components, any live host, and where results go
draugr mcp --scan=always   # additionally expose scan, without prompting
```

Every `*.saga.yaml` found within three directories of the working directory is also exposed as
an MCP **resource**, so a client can read the descriptor without a tool call.

| Tool | Purpose |
|---|---|
| `list_controls` | Which controls exist, what each checks, which scanner backs it, and the options each scanner accepts |
| `get_saga_schema` | The Saga schema this build enforces |
| `validate_saga` | Validate a descriptor, by `path` or by `content` |
| `check_tools` | Report which scanners are installed and what to run if any are missing |
| `summarize_report` | Rank an existing `results.sarif` by priority |
| `scan` | Run a scan and return the verdict, the scope it covered, and where the descriptor's publishers delivered it (requires `--scan=ask` or `--scan=always`) |

| Flag | Default | Description |
|---|---|---|
| `--scan` | `off` | Whether the assistant may start scans. `off` doesn't offer the tool; `ask` offers it and prompts for your approval on every call (needs a client supporting MCP elicitation — the scan is refused, not silently run, if it can't prompt); `always` offers it with no prompt, for sandboxes and CI. |

The server speaks MCP, not text — run by hand in a terminal it will look like it has hung,
because it's waiting for a client. See
[use Draugr from an AI coding assistant](../guides/ai-agents-mcp.md) for client setup and why
routing through Draugr beats letting the assistant run scanners itself.

---

## `draugr self-update`

Update the running `draugr` binary in place to the latest published release (or a specific
`--version`), verified against the release's **SHA-256 checksums** (mandatory) and its keyless
**cosign** signature (when the `cosign` CLI is present). It replaces the binary you're actually
running (`os.Executable()`), so there's no second copy or PATH confusion.

| Flag | Default | Description |
|------|---------|-------------|
| `--version` | latest | Target release to install (e.g. `0.16.0`) |
| `--check` | — | Report current vs latest available; make no changes |
| `-y, --yes` | — | Skip the confirmation prompt |

```bash
draugr self-update            # confirm, then update to the latest release
draugr self-update --check    # just report current vs latest
draugr self-update --version 0.15.0 -y
```

For CI, **pin a released version** rather than self-updating.

## `draugr version`

Print the version, commit, build date, and Go version.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit the same fields as JSON, for scripts and CI |

```bash
draugr version            # draugr 0.31.1 (commit 30862ef, built …, go1.26.5)
draugr --version          # the same bytes, under the spelling every other CLI uses
draugr version --json     # {"version":"0.31.1","commit":"30862ef","built":"…","go":"go1.26.5"}
```

Output goes to stdout in both forms, so `v=$(draugr version --json | jq -r .version)` works.

**`--version` prints exactly what `version` prints**, so a script parsing one parses the other.
It exists because container smoke tests, tool caches and version probes reach for the flag rather
than the subcommand, and an unknown-flag error reads as a broken binary.

## `draugr schema`

Print the Saga JSON Schema **this build enforces** (it's embedded in the binary).

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | — | Write to this file instead of stdout |
| `--fragment` | `false` | Print the [Saga fragment](../guides/saga-fragments.md) schema instead |

```bash
draugr schema                      # print it
draugr schema -o .saga.schema.json # pin editor validation to this exact build
draugr schema --fragment           # the schema for *.saga-fragment.yaml
```

A fragment is a different shape — no `release:`, and no policy — so it has a schema of its own. A
fragment checked against the Saga's schema reports a missing `release` on every valid file, which
is why the two file types are distinguishable by name.

Editors normally fetch the schema from draugr.dev, which needs network access and follows a
published version. A local copy pins validation to the Draugr you actually have, and works
offline — see [editor support](saga-schema.md#editor-support-autocomplete-hover-docs-validation).

## `draugr completion <shell>`

Generate a shell completion script (bash, zsh, fish, powershell).
