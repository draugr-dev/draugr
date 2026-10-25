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
| `--log-file` | - | Also append every record to this file, at `trace` level and unclamped |
| `--offline` | `false` | Make no network calls (also `DRAUGR_OFFLINE=1`) |
| `--config` | - | Machine/organization settings file, used instead of the discovered ones (also `DRAUGR_CONFIG`) |

**`--offline`** says once that this machine has no network, and every place Draugr would reach out
honors it. Optional fetches are skipped with a line saying so. A command whose whole purpose is to
download (`feeds update`, `tools install`, `self-update`) refuses and names what it would have
fetched. A scan runs against whatever each tool already has on disk, and a tool with nothing on disk
reports an error rather than a clean result.

`draugr doctor` lists every host a scan contacts besides its targets, per control, so a runner can
be prepared from that list rather than one failure at a time. See
[running air-gapped](../guides/air-gapped.md).

**Seeing what Draugr is doing.** `--log-level debug` narrates the run: what was planned, the
**exact command** handed to each scanner with its working directory, duration and exit code,
cache hits, findings per control, and aggregation.

```console
$ draugr scan . --controls iac --log-level debug
18:16:05 DEBUG  planned job control=iac scanner=trivy-config target=https://github.com/draugr-dev/draugr@ target_kind=repository
18:16:06 DEBUG  scanning control=iac scanner=trivy-config target_kind=repository
18:16:06 DEBUG  ran external tool tool=trivy argv="trivy fs --scanners misconfig --format json … /tmp/draugr-repo-964636929" duration=757ms stdout_bytes=105881 dir=/tmp/draugr-repo-964636929
18:16:06 DEBUG  ran external tool tool=trivy argv="trivy convert --quiet --format sarif /tmp/draugr-trivy-config-431477641.json" duration=48ms stdout_bytes=37967 dir=/tmp/draugr-repo-964636929
18:16:06 DEBUG  scan complete control=iac scanner=trivy-config findings=14 duration=903ms
```

**When a control fails.** A control whose scanner exits badly is reported as an error rather than
a pass, and the error carries the tool's own first line of output:

```
CONTROLS
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

Trace is verbose, and is for when the summarized line has not answered the question. Logs go to
stderr, so `2>trace.log` keeps them out of a report on stdout.

**`--log-file`** writes every record to a file at trace level, with each relayed stream whole. The
terminal keeps the `--log-level` asked for, and clamps a relayed stream with a note saying how much
was left out:

```bash
draugr scan .                       # nothing on screen but the report
draugr scan . --log-file draugr.log # …and the whole run in a file
```

The file is **appended**, not truncated, so a second run that reproduces a problem adds to the
first. It is written `0600` and never colored. A `--log-file` that cannot be opened **fails the
run** rather than being skipped.

**Reading a dense log.** The `console` format gives each part of a record its own weight, so the
shape of a line is legible before its content: the **message** strongest, because it is what you
scan for; the level colored; timestamps and attribute keys dimmed; values plain. An `error`
attribute and a non-zero `exit_code` are colored as well.

Color changes the rendering and never the text, so records stay greppable. `NO_COLOR=1`, a pipe
or a redirect give the same output without the escapes, and `--log-format json` is unaffected by
all of it.

Telemetry is opt-in and a no-op until an endpoint is set. Draugr exports OpenTelemetry traces and
metrics over OTLP and reads the standard variables, so anything that already collects OTLP needs
no Draugr-specific configuration:

| | |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | both signals, e.g. `http://localhost:4318` |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | traces alone, where they go somewhere else |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | metrics alone |

Setting none of them disables both exporters. The rest of the specification's variables (headers,
TLS, sampling) are read by the SDK and behave as they do everywhere else. Span attributes never
carry secrets.

---

## Environment

Every variable Draugr reads that you would set yourself. Flags win over variables, and variables
win over a settings file.

**Behavior**

| | |
|---|---|
| `DRAUGR_CONFIG` | the machine or organization settings file to read, instead of the discovered ones |
| `DRAUGR_OFFLINE` | make no network calls. Equivalent to `--offline` |
| `DRAUGR_NO_UPDATE_CHECK` | skip the check for a newer release, without disabling the rest of the network |
| `DRAUGR_NO_TIPS` | suppress the console's contextual tips |
| `NO_COLOR` | render without color. Honored whatever the terminal reports |

**Credentials.** Each is read at the moment it is needed and never written to a report, a log line,
a span attribute or a cache key.

| | Used by |
|---|---|
| `GITHUB_TOKEN` | `draugr survey github repos`; the `github`, `github-pr-comment` and `github-issue` publishers; `draugr tools outdated`, against GitHub's rate limit |
| `GITLAB_TOKEN` | `draugr survey gitlab projects`; the `gitlab-mr-comment` and `gitlab-issue` publishers |
| `AZURE_DEVOPS_EXT_PAT`, else `AZURE_DEVOPS_TOKEN` | `draugr survey azure repos` |
| `SYSTEM_ACCESSTOKEN` | the `azure-pr-comment` and `azure-work-item` publishers |
| `URLHAUS_AUTH_KEY` | the `urlhaus` scanner, the `threats` default. Free from <https://auth.abuse.ch/> |
| `VIRUSTOTAL_API_KEY` | the `virustotal` scanner, opt-in under `threats` |
| `DRAUGR_API_TOKEN`, `DRAUGR_API_URL` | the `draugr-api` publisher |

A publisher's `tokenEnv` names a different variable in place of its default. A descriptor names the
variable holding a credential and never the credential, because a descriptor is committed and a
token in one is a leaked token.

**Self-hosted forges**

| | |
|---|---|
| `GITHUB_API_URL` | GitHub Enterprise Server's API, including `/api/v3`, for `survey github repos` and the GitHub publishers |
| `GITLAB_URL` | a self-managed GitLab, for `survey gitlab projects` |
| `AZURE_DEVOPS_URL` | Azure DevOps Server, for `survey azure repos` |

**Observability**

`OTEL_EXPORTER_OTLP_ENDPOINT` and its per-signal variants, above.

In a pipeline Draugr also reads the CI platform's own variables to work out where it is running
and which change it is looking at. You do not set those; the platform does.

---

## `draugr init [dir]`

Scaffold a `draugr.saga.yaml` for a project (default: the current directory) from what its tree
holds. `sca`, `secrets`, `sast` and `iac` are always on; the tree adds scanners and stubs to them,
each with a comment naming the files behind it. Edit it, then `draugr scan`.

| Found in the tree | Written |
|---|---|
| `go.mod`, including one that requires nothing | `sast.gosec` · `config.reachability.analyzers: [govulncheck]` |
| Copied JavaScript: `*.min.js`, a file named for its release, anything under `vendor/` | `sca.retirejs` |
| `setup.py`, `pdm.lock` | `sca.grypeFs`, since Trivy reads neither |
| A requirements file named other than `requirements.txt`: `requirements-dev.txt`, `requirements/test.txt` | `sca.trivyFs.filePatterns` reaching it |
| Terraform, Helm, Kubernetes, a Dockerfile | named in the `iac` comment |
| A Dockerfile | a commented `images` control and image entry |
| An OpenAPI or Swagger document | a commented host with `spec: path:` pointing at it |
| A dependency file with no lockfile, or with no exact version | a comment on the component, and a row under `UNREAD` |

The console lists what was found under `FOUND` and the dependency files no scanner can take
packages from under `UNREAD`.

A directory below the root that holds its own dependency file or `go.mod` is a part of the
repository. By default the descriptor has one component and names the parts in a comment;
`--per-directory` writes a component for each, scoped with `paths:`, and the root component
`ignore:`s them.

A JavaScript workspace member stays with its workspace root, whose lockfile resolves it. A member
is a directory the root `package.json` names under `workspaces` (npm, Yarn, Bun), as an array or as
`packages:` in an object, or one `pnpm-workspace.yaml` names under `packages:`. A member with a
lockfile of its own, or a dependency file of another ecosystem, is still a part.

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | `draugr.saga.yaml` | Path to write, relative to the working directory rather than `[dir]` (`-` for stdout). With `--fragment`, the default is `[dir]/draugr.saga-fragment.yaml` |
| `-f, --force` | `false` | Overwrite an existing file |
| `--per-directory` | `false` | Write a component for each directory that holds its own dependency file |
| `--fragment` | `false` | Write a Saga fragment: one component, no release and no policy |

```bash
draugr init                 # write draugr.saga.yaml for the current project
draugr init -o - | less     # preview without writing
draugr init --per-directory # one component per directory with its own dependency file
draugr init services/payments --fragment    # a Saga fragment, component named for the directory
```

For an instant scan with no file at all, use zero-config `draugr scan .` (below).

## `draugr scan [saga.yaml | dir]`

Load a descriptor, run the applicable controls, and produce a pass/fail verdict. Prints a
human-readable **console** summary to stdout by default (`--format` for other formats).
**Exits non-zero when the verdict is `fail`.**

**A descriptor in the directory wins.** Point `scan` at a directory, or omit the argument, and it
uses the descriptor there if one exists. Everything that file declares applies: the controls chosen,
the components, and the exposure and criticality that drive prioritization.

A descriptor is any file in that directory, not below it, whose name ends in `.saga.yaml` or
`.saga.yml`:

```
draugr.saga.yaml    web.saga.yaml    .saga.yaml    api.saga.yml
```

If the descriptor cannot be read, the scan **fails** rather than falling back to zero-config.

**More than one descriptor stops the scan.** On a terminal it asks which one to use; anywhere else
it lists them and exits non-zero. Name the file to skip the question:

```bash
draugr scan ./web.saga.yaml
```

**With more than one component, the report breaks the verdict down by component**, each judged by
the same policy as the run, so the parts cannot disagree with the whole. Components with nothing
against them are listed as passing, and findings from project-wide controls (which belong to no
component) are counted separately.

**A surface with no control enabled is called out.** A component that declares repositories,
images, hosts, clusters or cloud accounts with every control for that surface off gets a
`not-checked` row under `CAVEATS`, naming the controls that are off:

```
CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do
  Component  What   Caveat       Why
  worker     hosts  not-checked  dast, headers, tls off
```

A caveat fails the run only when `--fail-on-caveats` or
[`config.gate.failOnCaveats`](saga-schema.md#configgate) lists its kind.

**Contextual tips.** After a console scan, up to two rows that depend on the run may be added to
`TRY`, in this order of precedence. None of them affects the verdict:

| Tip | Shown when |
|---|---|
| `--fail-on P2` | The gate is on severity, the run passed, and it carries P1 or P2 findings |
| `builtBy: upstream` | The `images` control has findings and no component or image declares `builtBy` |
| `--cache-dir <dir>` | The run took a minute or more and `--cache-dir` is unset |
| `draugr controls` | A declared surface has no enabled control |
| `draugr tools install <tool>` | A scanner that ran is on `PATH`, was not installed by Draugr, and is one Draugr can install |

`--no-tips` or `DRAUGR_NO_TIPS=1` turns them off.

### Installing a missing scanner

On a terminal, a scan that needs a scanner `draugr tools install` fetches and cannot find asks
before it starts:

```
semgrep and trivy are not installed, so iac, sast and sca would not run.
Install them now with draugr tools install semgrep trivy? [Y/n/never]
```

| Answer | Does |
|---|---|
| Enter, `y` or `yes` | installs them, at the version the config pins if it pins one, then scans |
| `n`, or anything else | scans without them; the affected controls read `<tool> not installed` |
| `never` | scans without them and writes `output.offerInstall: false` to `~/.draugr/config.yaml`, or to the file `--config` or `DRAUGR_CONFIG` names |

It asks only when stdin, stdout and stderr are all terminals, and never with `--offline`, so a
pipeline, an assistant and a redirected report scan as before. The tools a scan needs are the ones
[`draugr doctor`](#draugr-doctor-sagayaml) checks, narrowed by `--controls`. A tool Draugr does not
fetch is not offered.

### While a scan is running

A scan plans one job per repository, image, host and cluster and runs them concurrently. On a
terminal it redraws a progress display: how many jobs have finished, then a row per control and
scanner with its finished and total jobs.

```
Scanning 1/2
  ▸ secrets/gitleaks                   1/2
```

A row's mark is `·` before its jobs start, `▸` while one runs, `✓` when all have finished and `✗`
when they have finished and one failed. A row whose oldest running job has taken two seconds or more
shows how long, and the first line adds the run's elapsed time and the count of failed jobs. While a
scanner refreshes its data before the jobs start, the first line reads `Refreshing` and names the
data. The display is erased before the report.

It is drawn **only when stderr is a terminal**, so a report on stdout stays parseable when piped and
a CI log carries no frames. `--no-tips` and `DRAUGR_NO_TIPS=1` turn it off along with the tips.

### What the run cost

Under `--evidence`, the `run` row accounts for the run:

```console
$ draugr scan . --controls secrets --cache-dir .draugr/cache --evidence
…
  run         1 job in 16ms · secrets took the most scanner time, 15ms · 1 from cache, oldest 9m0s
```

The row holds, in order, the job count and the run's wall-clock time; the concurrency limit, where
the run had more jobs than it; the control with the most scanner time, summed across its jobs;
how many jobs were answered from [the cache](#using-the-cache-in-a-scan) and the age of the oldest
entry used; time spent waiting for a tool's own cache; and scanner data refreshes of a second or
more.

### Scoping a run

`--components` and `--controls` narrow a run to the named components and controls without
touching the descriptor:

```bash
draugr scan --components app,frontend
draugr scan --controls sca
draugr scan --components app --controls sca --log-level debug
```

**`--labels`, `--exposure` and `--criticality` select components by what they declare** rather
than by name, so the selection follows the descriptor as components are added.

```bash
draugr scan --labels team=web                  # what the web team owns
draugr scan --labels team=web --labels tier=1  # the web team's tier-1 components
draugr scan --exposure public                  # everything internet-facing
draugr scan --exposure public --criticality critical
```

Values within one flag are alternatives and the flags narrow together, so `--labels team=web
--labels team=payments` is either team and `--labels team=web --exposure public` is that team's
public components. `--labels` reads the component's own [`labels`](saga-schema.md), which is the
organization's vocabulary. `--exposure` and `--criticality` are Draugr's own, so a value that is
not one of them is refused by name:

```
draugr: --exposure: no such exposure "pubic" (want one of: public, authenticated, internal, restricted)
```

**A selector that matches nothing is an error**, not an empty run. The error offers the values
that key does have:

```
draugr: --labels team=nope matches no component (this descriptor uses team=platform, team=web)
draugr: --labels squad=web matches no component (no component declares label "squad")
```

The selector is resolved to component names before the run starts, so the verdict line, the
component list and the SARIF analysis category all describe what was covered. `results.sarif` also
records the selector itself.

The scope flags apply to one run and change nothing in the descriptor.

**A scoped run still gates**, and its verdict line names the scope:

```console
$ draugr scan --components web --controls secrets
DRAUGR  FAIL  storefront 1.0  (scope: 1 of 3 components; secrets)  567ms

 5 P1 0 P2 0 P3 0 P4

CONTROLS
  secrets  FAIL   5 P1
…
COMPONENTS
  web     FAIL   5 P1
  api     not scanned
  worker  not scanned
```

Components outside the scope are **listed as `not scanned`**, so the breakdown never shows a
skipped component as one that passed.

The scope travels into the artifacts too: `report.json` gains a `scope` object, and the SARIF
carries it as run provenance. Both are absent on an unscoped run.

**[`draugr diff`](#draugr-diff-basesarif-headsarif) refuses reports of different scope**, because
a finding outside the narrower scan would be reported as fixed. Two runs of the same scope compare
normally.

A component or control name that matches nothing is an **error** listing what the descriptor
declares:

```
draugr: --components: this descriptor declares no component "frontnd" (it has: api, web, worker)
```

The scope flags change **what runs**, and so the verdict.
[`--min-priority`](#what---min-priority-narrows) changes only what is *printed* from a full run.

**Zero-config.** A directory with no descriptor is scanned as one component with `sca`,
`secrets`, `sast` and `iac`. A note saying so is printed to stderr, so machine formats on stdout
stay clean.

```bash
draugr scan            # zero-config: scan the current repo
draugr scan ./service  # zero-config: scan another repo directory
draugr scan draugr.saga.yaml   # full control from a descriptor
```

The flag tables below follow the groups in `draugr scan --help`.

**What is scanned**

| Flag | Default | Description |
|------|---------|-------------|
| `--components` | - | Scan only these components; the verdict says what it covered |
| `--labels` | - | Scan only components carrying these `key=value` labels; repeat for more, one key twice means either value |
| `--exposure` | - | Scan only components declaring one of these exposures: `public`, `authenticated`, `internal`, `restricted` |
| `--criticality` | - | Scan only components declaring one of these criticalities: `critical`, `important`, `supporting` |
| `--controls` | - | Run only these controls; the verdict says what it covered |
| `--working-tree` | `false` | Scan local repositories as they are on disk, uncommitted work included. See [below](#--working-tree-for-the-loop-of-fixing-something) |

**What fails the build**

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-on` | `P1` | What fails the gate, in either vocabulary: a priority band (`P1`–`P4`) or a severity (`critical`, `high`, `medium`, `low`). Overrides [`config.gate`](saga-schema.md#configgate); `P1` applies when neither sets one |
| `--fail-on-priority` | - | Deprecated: write the band in `--fail-on`. Refused together with `--fail-on` |
| `--fail-on-caveats` | - | Kinds of caveat that fail the run as an error does: `not-checked`, `not-measured`, `unread-files`, `unread-checks`, `unbound-imports`, or `none`. Overrides [`config.gate.failOnCaveats`](saga-schema.md#configgate) |
| `--no-gate` | `false` | Report the verdict but exit 0 on a fail, for producing a report to compare later, where [`draugr diff`](#draugr-diff-basesarif-headsarif) is the gate |
| `--allow-scan-errors` | `false` | Treat a control whose scanner could not run as a warning rather than a failure. The verdict line then carries `partial`, with the number of targets not reached. A run that planned no jobs at all still fails |

**Exploitability data**

| Flag | Default | Description |
|------|---------|-------------|
| `--kev` | - | CISA KEV catalog: a file path, or `cache`/`auto` to read `~/.draugr/feeds`. A CVE on it is escalated to critical. Overrides `config.exploitability.kev` |
| `--epss` | - | FIRST EPSS scores: a file path, or `cache`/`auto` to read `~/.draugr/feeds`. A CVE at/above `--epss-threshold` is bumped one band. Overrides `config.exploitability.epss` |
| `--epss-threshold` | `0.5` | EPSS probability (0–1) that triggers a severity bump. Overrides `config.exploitability.epssThreshold` |

**Output**

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `console` | What to print: `console`, `markdown`, `json`, `sarif`, `vex`, `template` |
| `-o, --output` | - | Directory to write reports into: `report.json` and `results.sarif` unless `--report` says otherwise, and one SBOM per target when [`config.sbom`](saga-schema.md#sbom-generation) is set |
| `--report` | `json,sarif` | Formats to write into `-o`: `console`, `evidence`, `html`, `json`, `junit`, `markdown`, `sarif`, `vex`, and the `gitlab-*` reports. Replaces the default rather than adding to it. See [below](#--format-prints---report-writes) |
| `--view` | `findings` | What the report shows: `findings`, `actions` or `compact` |
| `--group` | - | Deprecated. `--group action` is `--view actions`, `--group none` is `--view findings` |
| `--evidence` | `false` | Console: also print what stands behind the verdict: tool provenance, what each control measured against, the scanned revision, and what the run cost. `--report evidence` writes the same content to a file |
| `--top` | `10`, or `3` per list under `--view actions` | Console: max findings to list in the ranked table, or under `--view actions` how many actions each list shows (`0` = all) |
| `--min-priority` | - | List findings at or above this priority band (`P1`–`P4`). Narrows what is printed; `results.sarif` and publishers keep the full set. See [below](#what---min-priority-narrows) |
| `--artifact-min-priority` | - | Also narrow the `-o` artifacts to this band, and record the band inside them. See [below](#what---min-priority-narrows) |
| `--compact` | `false` | Deprecated. Use `--view compact` |
| `--template` | - | Inline Go `text/template` (with `--format template`) |
| `--template-file` | - | Go `text/template` file (with `--format template`) |
| `--no-tips` | `false` | Suppress the console's contextual tips (also `DRAUGR_NO_TIPS`) |

`--view` takes:

- `findings`: a block per finding, saying what it is, what is known about it, and where.
- `actions`: a row per thing to do, saying how many findings it clears. See
  [what to fix first](../concepts/what-to-fix-first.md).
- `compact`: one line per finding; in `json` and `sarif` output, no indentation and no rule
  documentation. See
  [machine-readable output](../guides/reports-and-publishers.md#compact-output-for-tools-and-agents).

The `-o` report files carry every finding whatever the view. The ranked table's heading says
whether it is a shortlist or every finding, and `--top 0` also lists every row under `ERRORS` and
`CAVEATS`, where the default is ten each.

**Caching**

| Flag | Default | Description |
|------|---------|-------------|
| `--cache-dir` | - | Enable content-hash caching in this directory |
| `--cache-ttl` | `24h` | Cache entry lifetime (`0` = no expiry) |
| `--cache-read-only` | `false` | Read the cache but never write it, for a run whose results the next run should not reuse |
| `--cache-require-digest` | `false` | Do not cache an image identified only by a tag. Left off, such a result is still reused and the report names it. See [what a hit does and does not promise](../guides/caching-and-performance.md#what-a-hit-does-and-does-not-promise) |

**Running the scan**

| Flag | Default | Description |
|------|---------|-------------|
| `-j, --jobs` | `0` (auto) | Max scan jobs to run in parallel (`0` = one per CPU); reported as `stats.concurrency` |
| `--allow-effects` | - | Accept scanner effects for this run (`mutate`, `privilege`). `config.allowEffects` is the reviewed equivalent. See [below](#scanners-that-do-more-than-read) |
| `--no-publish` | `false` | Skip the descriptor's configured publishers (still writes `-o` artifacts and stdout) |
| `--policy` | `false` | Require the [organization's policy](#the-organizations-policy) check |

Under `--policy`, a descriptor publishing to no `draugr-api` server, a missing token, an unreachable
server or `--offline` is an error rather than `not checked`. With `--no-publish`, the policy check
runs only under `--policy`.

The `--cache-*` flags have counterparts in [`draugr.config.yaml`](#draugr-config) under `cache:`
(`dir`, `ttl`, `readOnly`, `requireDigest`), and `--view`, `--evidence` and `--top` under
`output:`. A flag on the command line wins over the file.

```bash
draugr scan draugr.saga.yaml
draugr scan draugr.saga.yaml -o out/ --fail-on medium
draugr scan draugr.saga.yaml --min-priority P2        # focus on what matters now
draugr scan draugr.saga.yaml --fail-on P2             # widen the default gate from P1 to P2
draugr scan draugr.saga.yaml --fail-on critical      # gate on severity instead of the band
draugr scan draugr.saga.yaml --cache-dir .draugr/cache
draugr scan draugr.saga.yaml -j 4                      # cap parallelism (or -j 1 for serial)
draugr scan draugr.saga.yaml --format markdown        # portable report (MR comment, wiki)
draugr scan draugr.saga.yaml --format json | jq .      # machine-readable
draugr scan draugr.saga.yaml -o out/ --report html    # shareable browser report
draugr scan draugr.saga.yaml -o out/ --report junit   # CI test panel
draugr scan draugr.saga.yaml --format template --template '{{.Verdict}}: P1={{.Priorities.P1}}'
```

**Output formats (`--format`).** stdout defaults to a human **console** summary (verdict,
priority/severity counts, "fix first"). `markdown` is a portable report for MR comments or wikis;
`json` and `sarif` are the machine formats; `vex` is an OpenVEX document; `template` renders your
own Go `text/template` (see [`config.publishers`](saga-schema.md#configpublishers) for the
available fields). `html`, `junit` and the GitLab formats are files, written with `--report` into
`-o`. To render several formats and deliver them somewhere in one run, declare
[`config.publishers`](saga-schema.md#configpublishers) in the Saga.

**Tuning parallelism (`-j`/`--jobs`).** By default Draugr runs up to one scan job per CPU. Trivy and
Semgrep are multi-threaded themselves, so on a small or busy machine a lower `-j` can finish
sooner; `-j 1` runs serially. The run's JSON `stats` reports the effective `concurrency` alongside
`jobs` (total jobs), `scans`, `cacheHits` and `deduped`.

It also reports where the time went, in milliseconds: `durationMs` (wall-clock), `byControlMs` (each
control's job time, summed across its jobs) and `toolWaitsMs` (time spent queueing for a tool's own
cache rather than scanning). Jobs run concurrently, so the per-control times add up to more than
the wall-clock. They are absent, not zero, when a run recorded no timings. `dataRefresh` lists
each scanner's data refresh before the jobs started, in milliseconds. The console puts the total
beside the duration when it is five seconds or more and at least a quarter of the run, and
`--evidence` names each refresh of a second or more.

**Severity bands.** The console reports each finding's severity band (critical, high, medium or
low), derived from its CVSS score where the scanner supplies one, and `--fail-on` takes the same
words:

| Severity band | From CVSS | `--fail-on critical` | `--fail-on high` | `--fail-on medium` | `--fail-on low` |
|---------------|-----------|:--------------------:|:----------------:|:------------------:|:---------------:|
| critical | 9.0–10.0 | fails | fails | fails | fails |
| high | 7.0–8.9 | passes | fails | fails | fails |
| medium | 4.0–6.9 | passes | passes | fails | fails |
| low | 0.1–3.9 | passes | passes | passes | fails |

The SARIF levels `error`, `warning` and `note` are accepted as `high`, `medium` and `low`. A word
that is neither a band nor a severity is **rejected**:

```
draugr: --fail-on: "severe" is neither a priority band (P1, P2, P3, P4) nor a severity (critical, high, medium, low)
```

A finding's band, not its SARIF level, is what a severity gate judges, so a CVSS 7.8 a scanner
emits as `warning` is `high` for the gate as it is in the report. A finding with no CVSS score
takes its band from the level its scanner assigned; a control may also apply a **floor** (a leaked
secret is never reported as low, however the scanner scored it).

**Priority** (P1–P4) is ranked from a finding's severity and the component's declared `exposure`
and `criticality` (see the [Saga reference](saga-schema.md)). A component that declares neither is
ranked as public and critical, so its bands follow severity alone; when no component declares
either, the console says so. See [prioritization](../concepts/prioritization.md).

**Exploitability (`--kev`/`--epss`)** raises a finding's severity by real-world signals. A CVE on
CISA's [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (confirmed
exploited) becomes critical; a CVE at or above the [EPSS](https://www.first.org/epss/) threshold
(predicted likely) is bumped one band. Both are optional and only affect findings whose rule id is
a CVE. [Using the cache in a scan](#using-the-cache-in-a-scan) says where the data comes from.

### Scanners that do more than read

Most scanners read an artifact and nothing else. A few send traffic to a target, tell a third party
about it, change something, or need elevated access, and each of those is declared as an **effect**
that Draugr shows before a scan and records afterwards. A scanner with the `mutate` or `privilege`
effect does not run until a descriptor accepts it, or `--allow-effects` does for one run.

See [what a scan does](../trust-and-operations/what-a-scan-does.md) for each effect and how to
accept one.

### Which build of each scanner ran

A scan runs whatever is on `PATH`, and the `scanners` row under `--evidence` records which build
of each tool that was:

```
scanners    gitleaks 8.30.1, trivy 0.69.3
unverified  semgrep 1.173.0 · not installed by Draugr
```

The first line lists, together, the builds at `pinned` or `signed`: in `~/.draugr/bin`, in the
install record, and still hashing to what was recorded. Every other build gets its own line with
the reason. The version of a tool Draugr installed comes from its install record; a tool brought
some other way is asked, and one that does not answer is listed without a version.

Where Draugr can install a tool the scan ran from elsewhere on `PATH`, `TRY` offers the command:

```
TRY
  draugr tools install semgrep   scan on builds Draugr fetched and checked
```

Each build is recorded at one of these levels:

| Level | What it means |
|---|---|
| `pinned` | Installed at the version Draugr ships, matching a checksum recorded in this build |
| `signed` | Installed at another version, matching checksums signed by the upstream's Sigstore identity |
| `checksum` | Installed, matching an unsigned checksums file fetched from the upstream |
| `unverified` | Installed, with nothing published to check it against |
| `external` | Not installed by Draugr, found on `PATH` |

An unsigned checksums file over HTTPS shows the download was not corrupted or truncated, without
showing the upstream published it.

None of this affects the verdict.

### How current each scanner's data is

Under `--evidence`, the `data` row lists each data source the run's scanners read, with the date
this machine downloaded it and, where the tool records one, the date its publisher built it:

```
data        trivy checks bundle downloaded 2026-10-17 · trivy vulnerability database published
            2026-10-16, downloaded 2026-10-17 · retire advisory database downloaded 2026-10-17
```

Dates are UTC. `refused as too old` marks a copy the tool will not use, which fails that tool's
scans. By default Grype refuses a database built more than five days ago, and
`GRYPE_DB_MAX_ALLOWED_BUILT_AGE` changes the limit. Refresh the copy with the tool's own update
command; on a runner without a network, copy a newer cache in, as
[running air-gapped](../guides/air-gapped.md) describes.

`report.json` carries the same entries under `scannerData`:

| Key | Holds |
|---|---|
| `tool`, `data` | the tool and the data source, as the row names them |
| `version` | the schema version of a Trivy or Grype database, the first twelve characters of the Trivy checks bundle's digest, or the Nuclei template release |
| `published`, `downloaded` | each an RFC 3339 time in UTC, absent where the tool records none |
| `tooOld` | the tool's own reason, for a copy it refuses |

[`draugr doctor`](#data) lists the same sources before a scan.

### `DESCRIPTOR`, under `--evidence`

A descriptor assembled from more than one file gets a `DESCRIPTOR` section naming each file, and
the `descriptor` evidence row summarizes it:

```console
$ draugr scan draugr.saga.yaml --evidence
…
DESCRIPTOR
  draugr.saga.yaml                        root · digest b2e3b3ae8794
  security/exclusions.saga-fragment.yaml  digest 8ba02e9af9a5
…
  descriptor  draugr.saga.yaml + 1 fragment · merged digest 186eb88ac44b
```

A local file carries the digest of its content. A fragment from another repository carries
`<repository>@<revision>` and, where the revision is not itself a commit, `commit <sha>` for the
commit it resolved to. A descriptor that is a single file gets no section.

### `--format` prints; `--report` writes

`--format` chooses what a run prints to stdout, and `--report` chooses which files it writes into
`-o`.

**`--format`** accepts the formats a person or a pipe reads: `console`, `markdown`, `json`,
`sarif`, `vex`, `template`. A document format is refused with the flag that writes it:

```
draugr: html is a document, not something to print: use `--report html` with `-o <dir>`
```

**`--report`** names the files written into the directory `-o` names:

```bash
draugr scan draugr.saga.yaml -o out/                          # report.json + results.sarif
draugr scan draugr.saga.yaml -o out/ --report html,junit      # report.html + report.junit.xml
draugr scan draugr.saga.yaml -o out/ --report vex             # openvex.json
draugr scan draugr.saga.yaml -o out/ --report html --format console
draugr scan draugr.saga.yaml -o out/ --report gitlab-codequality
```

`html`, `junit`, `evidence` and the GitLab formats (`gitlab-sast`, `gitlab-dependency-scanning`,
`gitlab-secret-detection`, `gitlab-container-scanning`, `gitlab-codequality`, `gitlab-cyclonedx`)
are `--report` only. `evidence` is a companion to a report rather than a replacement for one: it
holds what stands behind the verdict and none of the findings. A GitLab runner reads its formats
from the paths named in `artifacts: reports:`; see
[reports & publishers](../guides/reports-and-publishers.md#gitlabs-own-report-formats) for which
GitLab surface each one feeds, and on which tier.

`-o` on its own writes `report.json` and `results.sarif`. `--report` replaces that default rather
than adding to it.

A publisher in [`config.publishers`](saga-schema.md#configpublishers) keeps the same split: its
`reports:` names what to render and its `kind` names where to send it.

### `--working-tree`, for the loop of fixing something

`--working-tree` scans each local repository as it is on disk, uncommitted work included, so
fixing a finding needs no commit between scans:

```bash
draugr scan draugr.saga.yaml --working-tree
```

Under `--evidence`, the `scanned` row marks the revision with `+` and counts the uncommitted files:

```console
$ draugr scan . --controls secrets --working-tree --evidence
…
  scanned     github.com/draugr-dev/draugr commit 6acefbc6+ · working tree · 1 uncommitted file, not
              reproducible
```

The result is **not reproducible**: nobody else can check out what was scanned. These scans are
**never cached**, because two runs at one revision can read different files.

It reads a **copy**, not your checkout, so scanners cannot write into your files and `paths` /
`ignore` scoping prunes the copy. The copy holds `git ls-files -co --exclude-standard`: tracked
files plus untracked ones that are not ignored, so a `node_modules` or a local `.env` is left out as
a commit would leave it out.

A remote repository is **refused**, naming it:

```
draugr: --working-tree needs a local checkout, and https://github.com/acme/api.git is a remote: scan without the flag, or point the descriptor at a path
```

### What `--min-priority` narrows

`--min-priority` decides what a **run shows you**. It never decides what a run **records**:

| Output | Narrowed by `--min-priority`? |
|---|---|
| Console, markdown, HTML, JUnit, whether printed or written with `--report` | **Yes**, with a note saying how many were hidden |
| `--format json` / `--format sarif` on **stdout** | **Yes** |
| `-o <dir>/report.json` | Its **findings list** only. The priority counts still describe the whole run |
| `-o <dir>/results.sarif` | **No**, always complete |
| Configured publishers, including `github` code scanning | **No**. Always complete, and the run logs that it ignored the flag |

The files stay complete because **GitHub code scanning and
[`draugr diff`](#draugr-diff-basesarif-headsarif) both read a finding missing from a file as
fixed**.

#### Narrowing on purpose

These narrow a file deliberately:

- **`--artifact-min-priority P1`**, or **`minPriority: P1`** on a report in
  [`config.publishers`](saga-schema.md#configpublishers), narrows the written SARIF and JSON.
- **`draugr diff --format sarif`** emits only the findings a change introduced.

Both **record what they left out**: a narrowed SARIF carries a `draugr/min-priority` provenance
entry naming the band, as a scoped run records its scope.

An upload narrowed to `P1` resolves the P2–P4 alerts **for the ref and category it was uploaded
against**. A pull-request run uploads against the pull request's own ref and leaves the default
branch's alerts alone, while a narrowed upload from a push to the default branch resolves the
omitted alerts there.

`--min-priority` alone is for reading: a terminal, or an agent asking for the short list. With
`--format sarif` it also drops the rules that only the omitted findings referenced.

### The organization's policy

A descriptor that publishes to a [`draugr-api`](saga-schema.md#configpublishers) server is checked
against the organization's policy before any scanner starts, with the endpoint and token publishing
uses. The server judges the descriptor and words each verdict; Draugr shows what it says and acts on
it:

| A broken setting that | Does |
|---|---|
| refuses, and is in force | stops the run before any scanner starts, and the command exits non-zero |
| fails the gate, and is in force | runs the scan, then fails the gate naming the rule, whatever the findings say |
| observes, or is not in force yet | is shown, and changes nothing |

The scan lists each broken rule under `CONTROLS`, one item per line, then the profile that set it
and what it does:

```console
POLICY  version 7 · https://draugr.example
  threshold  failOn: P1 · required: P2 or stricter        PCI scope · fails the gate, since 2026-10-01
  scanners   sca scanners: trivy-fs · required: grype-fs  Default · observed
```

A run that could not ask says `POLICY  not checked` and why: no endpoint or token, `--offline`, or a
server that judges no policy. `--policy` makes that an error. A rule the server judges from the
run's findings rather than from the descriptor is decided when the run is published, and the
publisher fails the build if the policy fails the published run. `report.json` records the server,
the policy version and every verdict as
[`policy`](report-schema.md#telling-a-partial-run-from-a-clean-one). A scan with `--no-publish` is
published nowhere, so it asks nothing unless `--policy` is passed.

## `draugr explain <rule-id>`

Print what a scan's own report holds about one rule: its description, the detail its scanner
published, where the scan found it (up to five locations), and its reference link.

```bash
draugr scan draugr.saga.yaml -o out/
draugr explain kube-bench/cis/4.3.1 -r out/results.sarif
```

```
kube-bench/cis/4.3.1
Ensure that the kube-proxy metrics service is bound to localhost

DETAIL
  Modify or remove any values which bind the metrics service to a non-localhost address.
  The default value is 127.0.0.1:10249.

LOCATION
  kubernetes/prod-cluster

REFERENCE
  https://www.cisecurity.org/benchmark/kubernetes
```

`DETAIL` is left out when the scanner published nothing beyond the description.

| Flag | Default | Description |
| --- | --- | --- |
| `-r, --report` | - | The `results.sarif` to read. Without it, the first that exists of `.draugr/out/results.sarif`, `results.sarif`, `draugr-out/results.sarif` and `.draugr-out/results.sarif` |

The id can be given in full, or by its trailing `/`-separated segments: `4.3.1` and `cis/4.3.1`
both find `kube-bench/cis/4.3.1`, and `4.3` finds nothing. A whole id also matches regardless of
case. An abbreviation matching more than one rule lists them rather than choosing one.

A report holds only the rules its scan reported, so a rule the scan did not find is not there.

## `draugr diff [base.sarif] <head.sarif>`

Compare two scans and classify every finding as **new**, **unaccepted**, **accepted**, **fixed**,
**moved** or **unchanged**: the security delta of a change, typically a pull request's head against
its base branch. Inputs are the `results.sarif` files that
[`draugr scan -o`](#draugr-scan-sagayaml--dir) writes, which are always complete regardless of
`--min-priority`. Two reports of different [scope](#scoping-a-run) are refused.

**Accepted** is a finding somebody excused rather than fixed: an exclusion added, or a finding that
arrived already covered by one. **Unaccepted** is a finding whose exclusion was removed or reached
its `expires` date, so it counts again. **Still accepted** is a finding suppressed in `base` and
still suppressed in `head`; it counts toward the unchanged total and is never listed as a change.
Accepted findings are counted apart from fixed ones.

**Moved** is a finding reported under a different component in `head`, with the same tool, rule,
file, repository and suppression, and the same content hash or message. Splitting or renaming a
component moves every finding it held. Moves are listed in a `MOVED` table, one row per pair of
components, then a `PRIORITY CHANGED` table with a row for each finding whose priority changed with
its component.

New, unaccepted, accepted and fixed findings are listed in one `CHANGED` table, ranked by priority,
with what happened to each finding in its own column. Within a band, what needs somebody comes
before what does not. `--view actions` lists the changes as things to do instead. Above the table,
one strip per state counts the prioritized findings in `head` by band: new, unaccepted, accepted,
moved, unchanged and still accepted. A strip with nothing in it is not drawn, and fixed has none,
because a fixed finding is not in `head`.

```console
$ draugr diff head/results.sarif
DRAUGR DIFF  4 new

 new  3 P1 1 P2 0 P3 0 P4

Base: none, so every finding is new.

CHANGED  4, by priority
  Change  Priority  Severity  Rule                 Scanner      Location                    Upgrade
  + new   P1        high      CVE-2021-44906       trivy        package-lock.json:15        minimist 1.2.5 → 1.2.6
          Fixture: prototype pollution in minimist
…
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `console` | Output format: `console`, `json`, `markdown`, `sarif`. `sarif` emits the new findings only, for code scanning on a pull request |
| `--view` | `findings` | Console: how much of each row to show. `findings` adds the finding's own sentence under the row, `compact` is one line each, `actions` groups by the thing to do |
| `--top` | `0` | Console: how many changed findings to list (`0` = all), or how many actions under `--view actions`. Also caps the moved findings whose priority changed |
| `--min-priority` | - | Report only new findings at or above this priority band (`P1`–`P4`), plus new findings with no priority; fixed and unchanged are unaffected. Narrows the diff, never the scans it was computed from |
| `--repository` | - | Keep only new findings from this repository, plus those belonging to none (an image, a host). For a code-scanning upload, whose paths anchor to one checkout |
| `--fail-on-new` | - | Fail if a new finding is at or above this: a priority band (`P1`–`P4`) or a severity (`critical`, `high`, `medium`, `low`). Without it, the diff exits 0 |
| `--fail-on-new-priority` | - | Deprecated: write the band in `--fail-on-new`. Refused together with `--fail-on-new` |
| `--publish` | `false` | Post the diff as a sticky pull-request comment. Picks `github-pr-comment`, `azure-pr-comment` or `gitlab-mr-comment` from the CI environment; no-ops off a PR |

The gate reads **new** only. Accepted, unaccepted and moved findings do not trip it, and each is
reported.

**The head alone.** The pull request that adds a repository's first descriptor has nothing at its
base to scan. `draugr diff head/results.sarif`, with no base report, compares the head against no
findings, so every finding in it is new and `--fail-on-new` gates on them, and the report says there
was no base. A base path that names no file is still an error. The GitHub Action and the GitLab and
Azure DevOps templates diff the head alone when the base commit lacks the descriptor, so the first
pull request that turns Draugr on is gated like any other.

Where no gate is asked for, the report states no verdict, and `draugr diff` exits 0.

```bash
draugr diff base/results.sarif head/results.sarif                     # console delta
draugr diff base/results.sarif head/results.sarif --format markdown   # MR comment
draugr diff base/results.sarif head/results.sarif --fail-on-new P1
draugr diff base/results.sarif head/results.sarif --publish           # sticky PR comment (in CI)
```

**Differential gating.** `--fail-on-new` fails a pull request only for findings it
*introduces*, not for the backlog already on the base branch, and the command exits non-zero when
the gate trips. A typical CI setup scans `main` on push and stores `results.sarif` as an artifact,
scans the pull request, then diffs the two.

**Both sides are committed revisions** unless a scan used
[`--working-tree`](#--working-tree-for-the-loop-of-fixing-something). A repository is cloned before
it is scanned, whether it was given as a URL or a local path, so scanning, editing and re-scanning
locally produces two identical files and an empty diff. Commit between the two scans, or point
`revision` at each revision in turn. See
[URLs and paths](saga-schema.md#where-a-repository-comes-from-urls-and-paths).

**Finding identity.** A finding in both reports is matched first by a hash of the lines around it,
then by tool, rule, file, message, component and repository, and then by each of those again
without the component, which is how a moved finding is found. The line number and the severity are
never part of it, so a finding that moved within a file or was re-scored is unchanged rather than
fixed and new. The [diff guide](../guides/pr-diff.md#what-counts-as-the-same-finding) has the
detail.

---

## `draugr survey`

Discover what an application is made of and write it into a descriptor.

Each surveyor is its own subcommand:

| Command | Discovers |
|---|---|
| `draugr survey k8s images` | unique container images running in a cluster, with their digests |
| `draugr survey k8s cluster` | the cluster itself, as a component's `kubernetes:` entry |
| `draugr survey github repos` | repositories in a GitHub organization |
| `draugr survey gitlab projects` | projects in a GitLab group, subgroups included |
| `draugr survey azure repos` | Git repositories in an Azure DevOps organization or project |
| `draugr survey provenance` | who signs the images the descriptor already declares |

`--k8s-images`, `--k8s-namespace` and `--github-org` are not flags; use the subcommands above.

| Flag | Applies to | Default | Description |
|------|------------|---------|-------------|
| `--context` | `k8s images`, `k8s cluster` | the current context | Kubeconfig context to survey |
| `--namespace` | `k8s images` | every namespace | Describe only this namespace; repeat for several |
| `--namespace` | `k8s cluster` | - | The component owns this namespace rather than the whole cluster; repeat for several |
| `--no-exposure` | `k8s images` | `false` | Leave each component's `exposure` unset rather than proposing it |
| `--org` | `github repos` | - | The GitHub organization to discover repositories in. Required |
| `--group` | `gitlab projects` | - | The GitLab group to discover projects in, subgroups included. Required |
| `--org` | `azure repos` | - | The Azure DevOps organization to discover repositories in. Required |
| `--project` | `azure repos` | - | Limit discovery to one project |
| `--trust-root` | `provenance` | - | A Sigstore trusted-root file, for an organization running its own Sigstore |

Shared by all of them:

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | stdout | Write the descriptor here, adding to the one already at that path |
| `--replace` | `false` | Overwrite the descriptor at `--output` instead of adding to it |
| `--fragment` | `false` | Write a [Saga fragment](#writing-a-fragment-instead-of-a-descriptor) |
| `--name` | - | Project name for a newly created descriptor |
| `--version` | - | Release version for a newly created descriptor, omitted when empty |

`provenance` reads `--output` as well as writing it: the images it asks about are the ones that
descriptor already declares. A descriptor that does not exist yet, `--replace`, or a descriptor that
declares no images is an error.

### Discovering who signs your images

`survey provenance` writes `signers:` from the identities that sign the descriptor's images
today. A job calling a reusable workflow is signed as that workflow's repository rather than as
the caller, which is the identity this reads.

```bash
draugr survey provenance -o draugr.saga.yaml
```

It writes the exact identity and the exact image, never a pattern, and groups images sharing an
identity under one signer. An unsigned image produces no signer and is not an error.

**Read what it proposes.** A signer derived from what signs an image today passes the check by
construction, so it catches the signature changing and does not show that today's signer is the
right one. The command names each identity it adopted and the image it came from, and writes the
same note beside the value in the descriptor.

An organization running its own Sigstore passes `--trust-root`, naming the same file
`config.controls.provenance.trustRoot` does.

### Writing a fragment instead of a descriptor

`--fragment` writes a [Saga fragment](../guides/saga-fragments.md) for a descriptor to include. It
holds components, and from `survey provenance` the `provenance.signers` a fragment may carry.

```bash
draugr survey k8s images --namespace team-a --fragment -o team-a.saga-fragment.yaml
```

A fragment carries no `release:`, so `--name` and `--version` are refused alongside it. It enables
no controls either; the descriptor that includes it decides what runs.

`draugr validate` and a `fragments:` reference both decide what a file is from its suffix, so with
`--fragment` an `-o` path must end in `.saga-fragment.yaml` (or `.yml`). The check runs before the
survey connects to anything. Without `-o`, the fragment goes to stdout.

### Not proposing an exposure

`--no-exposure` leaves `exposure` unset rather than proposing it from cluster topology:

```bash
draugr survey k8s images --no-exposure -o draugr.saga.yaml
```

The topology lookups are then not made, so a credential that cannot read Ingresses, Services and
NetworkPolicies produces no warnings about them. Use it when `draugr classify` is where exposure
gets decided.

Auth: each forge surveyor reads a token from the environment; the Kubernetes surveyors use your
ambient kubeconfig (`KUBECONFIG` / `~/.kube/config` / in-cluster).

**Without a token, every forge answers with the public repositories only**, and the survey warns
that the descriptor is missing every private one.

| Forge | Token | Self-hosted instance |
|---|---|---|
| GitHub | `GITHUB_TOKEN` | `GITHUB_API_URL`, including Enterprise Server's `/api/v3`. GitHub Actions sets it on a GHES runner |
| GitLab | `GITLAB_TOKEN` | `CI_API_V4_URL`, which a runner sets, then `GITLAB_URL`, then `CI_SERVER_URL` |
| Azure DevOps | `AZURE_DEVOPS_EXT_PAT`, else `AZURE_DEVOPS_TOKEN`. Needs the **Code (read)** scope | `AZURE_DEVOPS_URL`, including its collection |

```bash
draugr survey github repos --org my-org -o draugr.saga.yaml
draugr survey gitlab projects --group my-group -o draugr.saga.yaml
draugr survey azure repos --org my-org -o draugr.saga.yaml
draugr survey k8s images --namespace prod -o draugr.saga.yaml
```

**`draugr survey azure repos` takes `--project` or leaves it out**: with it, the survey covers that
project's repositories; without it, the whole organization's.

```bash
draugr survey azure repos --org my-org --project Platform -o draugr.saga.yaml
```

**`--namespace` may be repeated, and each one becomes its own component** with its own proposed
exposure:

```bash
draugr survey k8s images --namespace payments --namespace checkout -o draugr.saga.yaml
draugr survey k8s images --namespace payments,checkout -o draugr.saga.yaml   # equivalent
```

With no `--namespace`, every namespace is described, each as its own component with its own
images and proposed exposure. `--namespace` limits which namespaces are described.

**It says what it wrote.** A survey that writes a file reports the path and what is now in it, on
stderr so a descriptor sent to stdout stays a descriptor:

```
wrote draugr.saga.yaml · 12 components, 12 repositories
```

A survey that added to an existing descriptor says `merged into <path>` and what it contributed,
and one that discovered nothing says the descriptor scans nothing. The line is printed only with
`-o`.

**The output is scannable as written.** Discovery enables the controls for the surfaces it found:
repositories enable `sca`, `secrets`, `sast` and `iac`; images enable `images`; hosts enable
`headers` and `tls`; clusters enable `kubernetes`. `dast` is never enabled this way, because it
sends attack traffic at a live service.

**A control already configured is never touched**, including one set to `enabled: false`.

**Several surveys can write one descriptor**: each folds into the descriptor already at `--output`,
which is also how discovery is added to a descriptor maintained by hand.

Unless `--no-exposure` is given, `k8s images` **proposes each component's `exposure`** from its
namespace's topology: an Ingress or a `LoadBalancer` or `NodePort` Service → `public`, a
NetworkPolicy → `restricted`, otherwise `internal`. Where none of them can be read, nothing is
proposed. Each proposal is listed on stderr with the value chosen:

```
exposure proposed from cluster topology, not confirmed. Run `draugr classify` to set it:
  payments  public
```

A component that already carries an exposure keeps it and is not listed. Confirm the rest, and set
`criticality`, with [`draugr classify`](#draugr-classify-sagayaml--directory).

---

## `draugr classify [saga.yaml | directory]`

A guided wizard that sets each component's **`exposure`** and **`criticality`**, the two inputs to
finding prioritization, and writes them back into the descriptor (preserving comments and
formatting). It asks a few questions per component and derives the values. By default it asks only
about components missing either one.

Finds the descriptor the same way [`draugr scan`](#draugr-scan-sagayaml--dir) does: with no
argument, or with a directory, it uses the `*.saga.yaml` or `*.saga.yml` there. With more than one,
it asks which on a terminal and otherwise exits naming them. A directory holding none is an error,
because there is no descriptor to write the answers into.

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Re-classify every component, not just unclassified ones |
| `--components` | *(all)* | Only these components, by name. Naming one re-asks about it even if it is already classified |

A name that matches no component is an error, suggesting the closest name where one is close and
otherwise listing the components that exist.

```bash
draugr classify                              # the descriptor in this directory
draugr classify draugr.saga.yaml             # a specific file
draugr classify --components gateway,api     # redo two, leave the rest alone
```

---

## `draugr validate [saga.yaml | glob ...]`

Parse each descriptor, resolve `${{ VAR }}` references, and check it against the schema and the
controls and report formats this build provides, without running any scanners. It needs no scanner
installed, so it suits a pre-commit hook, a CI lint step, or an editor; a fragment from another
repository is fetched with `git`. **Exits non-zero if any file is invalid.**

Accepts paths and globs, and with no arguments discovers every `*.saga.yaml` and
`*.saga-fragment.yaml` (and their `.yml` forms) beneath the current directory, useful in a repo
holding one descriptor per service. `.git`, `node_modules`, `vendor` and `dist` are skipped.

**A fragment is checked as a fragment**, against the fragment schema, so its missing `release:`
is not an error.

```bash
draugr validate                          # every descriptor in the repo
draugr validate draugr.saga.yaml         # one file
draugr validate 'services/*/*.saga.yaml' # a glob (quote it, so the shell doesn't expand it first)
draugr validate azure.saga.yaml --resolved  # print the descriptor with every fragment merged
```

With more than one file, each is reported on its own line, then a count:

```console
$ draugr validate
✓ draugr.saga.yaml is valid
✗ svc-a/api.saga.yaml
    parse saga: unknown field "componnets" in the top level. Check the spelling, or see https://draugr.dev/docs/latest/reference/saga-schema/
✗ svc-b/web.saga.yaml
    parse saga: unknown field "failOnn" in config.gate. Check the spelling, or see https://draugr.dev/docs/latest/reference/saga-schema/
✗ svc-c/worker.saga.yaml
    parse saga: release.name was removed: it named the project, which is what the top-level `project` names. Move the value there, `project: payments-api`, and a release keeps only its version
draugr: 3 of 4 Saga file(s) invalid
```

The section named is the path you write, which is also the heading to look for in the
[Saga schema](saga-schema.md). A key that was removed says so and where its value belongs. A single
file's error is printed on its own, as `draugr: parse saga: …`. A valid file can carry warnings,
marked `!`, and notes, marked `·`, on the lines under it.

A pattern that matches nothing is an error:

```
draugr: no files match "nothing/*.saga.yaml"
```

### `--resolved`

Print the descriptor with every [fragment](../guides/saga-fragments.md) merged in, each source
named in a comment at the top. A descriptor with no fragments says so there.

```bash
draugr validate azure.saga.yaml --resolved
```

```yaml
# Resolved Saga, every fragment merged. Generated by `draugr validate --resolved`.
# Valid input: comments are the provenance, so this can be scanned as it stands.
#
# root:     azure.saga.yaml
# fragment: services/payments/draugr.saga-fragment.yaml
# fragment: https://github.com/acme/platform.git@v2.4.0 (40d23df24acc) components/api/draugr.saga-fragment.yaml
```

Provenance is carried in comments, so the output is **also a valid descriptor**:

- **Flatten it to cross an air gap.** Resolve where there is network, scan the result where there
  is none. See [running air-gapped](../guides/air-gapped.md).
- **Pin it.** Each remote fragment is recorded at the commit it resolved to, so a flattened copy
  behaves as a lockfile.
- **Diff it in CI.** Commit the resolved descriptor and fail when it stops matching, so a one-line
  `fragments:` change is reviewed by its effect rather than its cause.
- **Query it.** `draugr validate azure.saga.yaml --resolved | yq '.components[].name'`

The `fragments:` block is dropped from the output, since everything it named is already merged
in. `--resolved` takes one descriptor at a time.

## `draugr doctor [saga.yaml]`

Preflight the environment: report which external scanner tools are **present, missing, or out of
date**, with an install hint for each. Given a descriptor, it first loads it and reports a
parse or schema error, then checks only the tools needed by the scanners its enabled controls
select (plus `git` for repository targets and `syft` when `config.sbom` is enabled), then checks
that each [target](#targets) the scan would read is reachable from this machine. It does not check
control names or report formats; [`draugr validate`](#draugr-validate-sagayaml--glob-) does.

With a descriptor, it **exits non-zero** when:

- the descriptor cannot be loaded, or a required tool is missing or has no data;
- a target check fails;
- the organization's [policy](#policy) would refuse or fail the scan, or a `draugr-api` publisher
  has an endpoint without a token or a token without an endpoint;
- `--strict`, `--policy` or `--fail-on-uncovered` applies, as the flag table says.

So it gates CI: `draugr doctor saga.yaml && draugr scan saga.yaml`.

**Without a descriptor it is an inventory.** It lists every tool Draugr can use and which are
present, and exits zero when tools are missing, because nothing has been selected. Tools that back
only opt-in scanners, such as `kube-bench` and `grype`, are needed only by a descriptor that enables
them. The `kubernetes` control's default scanner reads the Kubernetes API directly, so it needs no
binary.

A tool is also reported as unusable (`✗ no data`) when it is installed but its supporting data is
not: `kube-bench` without its `cfg/` benchmarks, `nuclei` without its templates.

### A tool that is not the version Draugr tested

Draugr pins a version of each tool it can install, and its own suite runs against that build. A
tool on `PATH` at another version, from a distribution package or installed with `--version`, has
its row say which version was tested, and one line under the table counts them:

```console
$ draugr doctor --offline
…
TOOLS
Tool         Status     Version  Notes
…
trivy        ✓ found    0.69.3   /usr/bin/trivy · tested against 0.74.0
4 tools are not the version Draugr tests. `draugr tools install --force` installs the tested build.
```

The line is a note, not a failure, unless `--strict` is given. An older scanner can find fewer
things than the tested build.

### Targets

Given a descriptor, doctor plans the scan and checks each target the plan reads, with this machine's
network and credentials:

| Kind | Check | Passes when |
|------|-------|-------------|
| `repository` | resolves the revision; a full commit name is looked up in the repository | `git` resolves it |
| `paths` | reads the tree at that commit | every entry of the component's `paths` is committed there |
| `image` | the local Docker daemon, then the registry's manifest, with the credential `docker login` stored | either one has the image |
| `host` | opens a TCP connection, and completes the TLS handshake for `https` | the connection opens |
| `cluster` | resolves the kubeconfig context the cluster names, or the current one, and asks its API server for its version | the API server answers |
| `account` | asks Google Cloud whether the Application Default Credentials can read the project | they hold `resourcemanager.projects.get` on it |
| `file` | reads each file in `components[].imports` | it opens and is SARIF 2.1.0 |

A target two components share is checked once. A certificate this machine does not trust still
passes, with the reason in the row, because the scanners that probe an endpoint do not verify it.

```console
$ draugr doctor draugr.saga.yaml
TARGETS
Kind        Target                                              Result
repository  https://github.com/draugr-dev/draugr-demo.git@main  ✓ resolves to a103420078f4
paths       web                                                 ✓ in the tree at a103420078f4
paths       services/api                                        ✗ paths "services/api": not in the repository at a103420078f4
image       python:3.8-slim                                     ✓ in the local Docker daemon
image       ghcr.io/acme/api:2.1                                ✗ 403 forbidden, no credential for ghcr.io
```

The scope flags `draugr scan` takes narrow the target checks to the components and controls they
select; the tool, network and data lists still cover the whole descriptor, and without a descriptor
the flags do nothing. `--offline` skips every check that needs the network and marks each
`not checked: --offline`, while a local repository and the local Docker daemon are still checked.
It also skips the [policy](#policy) check, and a descriptor with a fragment from another
repository cannot be loaded under it.

### Policy

Given a descriptor that publishes to a `draugr-api` server, doctor asks that server what the
organization's policy makes of it, as [`draugr scan`](#the-organizations-policy) does, and lists
every rule that reaches the project, passing and broken, with what its setting does to a run that
breaks it:

```console
$ draugr doctor draugr.saga.yaml
POLICY  payments · version 7 · https://draugr.example
Rule       Profile    Result                                                If broken
threshold  PCI scope  ✗ failOn: P1 · required: P2 or stricter               fails the gate, since 2026-10-01
upgrade    Default    ✓ fixes.upgrade: minor · required: minor or stricter  fails the gate, since 2026-10-01
licenses   Default    – judged at publish                                   observed
```

A rule marked `–` is one the server judges from the run's findings rather than from the descriptor,
or one that asks nothing of this project. Doctor exits non-zero where a scan of the descriptor would
be refused or would fail its gate. With neither an endpoint nor a token it prints
`POLICY  not checked · no $DRAUGR_API_URL or $DRAUGR_API_TOKEN`, and `--policy` makes that an
error; with only one of the two it is an error either way. The token is the project's ingest token,
which belongs in CI.

### Network

Doctor lists every host a scan contacts besides its targets, per control: the reference data each
scanner fetches, and the third party a disclosing scanner tells about a target. Given a descriptor,
the list holds only the scanners that scan runs, which makes it the egress allowlist for that
runner. Without one, it holds every control.

```console
$ draugr doctor draugr.saga.yaml
NETWORK  (besides its targets · --offline stops all of it)
  draugr scan
    sca      ghcr.io               vulnerability database · before the scan
             mirror.gcr.io         vulnerability database · before the scan
    threats  urlhaus-api.abuse.ch  learns each host's name
```

`before the scan` data is fetched once per run and can be put on the machine in advance; `every
scan` data is fetched by the tool on each invocation. [Running air-gapped](../guides/air-gapped.md)
covers both.

### Data

Doctor lists the data each scanner reads as it stands on this machine, as a scan's
[`--evidence`](#how-current-each-scanners-data-is) does. Given a descriptor, it lists the scanners
that scan runs; without one, every scanner:

```console
$ draugr doctor draugr.saga.yaml
DATA
  retire advisory database downloaded 2026-10-17
  trivy vulnerability database published 2026-10-16, downloaded 2026-10-17
  trivy checks bundle downloaded 2026-10-17
```

Doctor reads what the tools left on disk and downloads nothing. `--json` carries the entries under
`data`, in `report.json`'s `scannerData` form. A tool that reports nothing about its data has no
line, and neither does one that is not installed, which `TOOLS` already reports as missing.

### What nothing is looking at

Doctor lists each surface a component declares with every control for it off, from the same
check that gives [`draugr scan`](#draugr-scan-sagayaml--dir) its `not-checked` caveats:

```
NOT CHECKED
  Component  Surface  Controls off
  api        hosts    dast, headers, tls
  api        images   images
```

The list is **reported, not failed**, unless `--fail-on-uncovered` is passed or
`config.gate.failOnCaveats` lists `not-checked`. A missing tool is reported first. After it, an
`UNTRACKED` block names any component no issue publisher selects.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit the report as JSON instead of tables. A tool not at its pin carries `testedVersion` |
| `--fail-on-uncovered` | `false` | Exit non-zero when the descriptor declares a surface no enabled control looks at. Also the behavior when [`config.gate.failOnCaveats`](saga-schema.md#configgate) lists `not-checked` |
| `--strict` | `false` | Exit non-zero when a tool is not the version Draugr tests. Without a descriptor, applies only when no tool is missing |
| `--policy` | `false` | Exit non-zero when the organization's policy could not be checked, as well as when a scan would be refused or fail by it |
| `--offline` | `false` | Skip the check for a newer draugr release, the policy check, and every target check that needs the network (`DRAUGR_NO_UPDATE_CHECK=1` skips only the release check) |
| `--components` | - | Check only the targets of these components |
| `--controls` | - | Check only the targets these controls would read |
| `--labels`, `--exposure`, `--criticality` | - | Select components as [`draugr scan`](#draugr-scan-sagayaml--dir) does |

The JSON's top-level fields are `draugr`, `descriptor`, `tools`, `missing`, `targets`, `policy`,
`data` and `uncoveredSurfaces`.

```bash
draugr doctor                       # inventory: what Draugr can use, and what you have
draugr doctor draugr.saga.yaml      # check only what this descriptor needs
draugr doctor --json draugr.saga.yaml
draugr doctor --fail-on-uncovered draugr.saga.yaml   # and fail if something is unexamined
draugr doctor --components web draugr.saga.yaml     # only web's targets
draugr doctor --offline             # no network: skip the update check and remote targets
```

Doctor also reports the running Draugr version and, best-effort (unless `--offline` /
`DRAUGR_NO_UPDATE_CHECK`), whether a newer release is available, nudging [`draugr
self-update`](#draugr-self-update). The check has a short timeout and never blocks or fails the
command.

Doctor never installs anything; [`draugr tools install`](#draugr-tools-install-tool) provisions
missing tools. The only repository data it fetches is what its target checks read and fragments
from other repositories.

---

## `draugr tools`

Provision and inspect the external scanners Draugr runs. Installs are **opt-in and
verified**, and a scan never installs a tool.

### `draugr tools outdated`

Asks each tool's upstream what it publishes now and reports it beside the version this Draugr
installs. Nothing is downloaded and nothing on disk changes. Refused under `--offline`.

```console
$ draugr tools outdated
Tool         Pinned   Upstream
cosign       3.1.3    3.1.3     current
gitleaks     8.30.1   8.30.1    current
…
trivy        0.74.0   0.76.0    draugr tools install trivy

6 of 12 behind the version their upstream publishes.
```

A tool whose upstream could not be asked shows `?` and `could not ask:` with the reason, and the
last line adds how many could not be asked. `draugr tools install <tool>` installs the pinned
version; `--version` installs another.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Write the comparison as JSON, for a pipeline proposing a bump |

Being behind does not fail the command. It exits non-zero only when a tool could not be asked, in
both output modes.

In the JSON, each tool has `tool`, `pinned`, `latest` and `behind`. A tool that could not be asked
carries `error` and has `behind: false`, the same value a current tool has, so check `error` or the
exit code rather than `behind` alone.

### `draugr tools install [tool...]`

Download **pinned** tool builds, verify each against a digest **recorded in Draugr** (a SHA-256
taken from the upstream checksums files for a release binary), and install them into
`~/.draugr/bin`, which Draugr **adds to `PATH` automatically**, so `scan` and `doctor` use them with
no shell config. Refused under `--offline`, naming the tools it would fetch.

**What gets installed.** `--saga` installs the tools that descriptor's scan will run and nothing
else. With no arguments it reads the current directory the way `draugr scan` does: it installs what
the descriptor there runs, or, with no descriptor, what a zero-config scan runs, and says which on
its first line. With more than one descriptor it asks which on a terminal and otherwise exits
naming them. `--all` installs everything this host can have. `--all`, `--saga` and a tool list are
refused in combination.

**Some are built from a package, not downloaded as a binary.** `govulncheck` needs Go 1.21 or newer,
`retire` needs Node 18 or newer, and `semgrep` needs Python 3.10 or newer, because none publishes a
release binary. With `--all`, a tool whose Go or Python is missing or too old, or whose `npm` is
missing, is **skipped and named** with the command to run once it is there, and the rest install:

```
– govulncheck: govulncheck is distributed as a Go package and no `go` is on PATH, install Go 1.21
  or newer from https://go.dev/dl/, or install it yourself with `go install golang.org/x/vuln/cmd/govulncheck@v1.8.0`
3 tools skipped, this host has no runtime to build them with. Install one and run
`draugr tools install govulncheck retire semgrep`.
```

Each skipped tool gets its own `–` line. A Node older than 18 is a failure rather than a skip.
Naming a tool whose runtime is missing, as in `draugr tools install govulncheck` on a host without
Go, fails and exits non-zero. `draugr tools list` names the runtime each one needs.

| Flag | Default | Description |
|------|---------|-------------|
| `-y, --yes` | `false` | Skip the confirmation prompt |
| `--dry-run` | `false` | Print the install plan and exit |
| `--force` | `false` | Reinstall even when the pinned build is already present, which also repairs a modified binary |
| `--version` | - | Install this version instead of the one Draugr ships. Takes exactly one named tool |
| `--saga` | - | Install only the tools that descriptor's scan will run |
| `--all` | `false` | Install every tool Draugr can provision |

```bash
draugr tools install --saga draugr.saga.yaml   # only what this project's scan runs
draugr tools install trivy      # just one
draugr tools install --all      # plan → confirm → the whole catalog, into ~/.draugr/bin
draugr tools install --dry-run  # preview the plan, change nothing
draugr tools install -y         # non-interactive
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

`--version` overrides that for a single invocation.

Draugr **installs a version it cannot vouch for**, such as a fork, a release candidate or a build
newer than this release, and records its verification
[level](#which-build-of-each-scanner-ran), which appears in every report the tool produces. It
**refuses** a download that does not match a checksum the upstream published.

The plan's `Verify` column says which you are getting before anything is downloaded:

| Verify | Meaning |
|---|---|
| `sha256` | the pinned build, against a SHA-256 recorded in Draugr |
| `sha256 + cosign` | the same, and the upstream's cosign signature over its checksums file |
| `upstream cosign`, `upstream sha256` | another version, against what the upstream signed or published |
| `unverified` | another version, with nothing published to check it against |
| `sha256 (+deps)`, `sha512 (+deps)`, `checksum db (+deps)` | `semgrep`, `retire` and `govulncheck`, with every dependency checked too |
| `-` | nothing to install: the tool is already current, or Draugr cannot provision it |

**`--saga` installs what a descriptor needs**, resolved the same way
[`draugr doctor`](#draugr-doctor-sagayaml) decides what to check: the enabled controls, and the
scanners those controls will select. Where a descriptor needs something Draugr cannot provision
(`kubectl`, `git`, `prowler`) the plan **names it** before the table.

**Tools already current are not downloaded again.** The plan marks a tool `already at <version>`
when the copy on `PATH` reports the pinned version, and when every planned tool is current the
command prints `Everything is already current.` and stops without asking. Otherwise each tool's
result is printed, and a release binary in `~/.draugr/bin` whose checksum still matches the
install record is left alone and counted:

```
✓ syft 1.51.1 → /home/you/.draugr/bin/syft (sha256 verified)
7 tools unchanged.
```

A binary in `~/.draugr/bin` that no longer matches its record is replaced, and a changed pin also
reinstalls. `semgrep`, `retire` and `govulncheck` are rebuilt whenever the command installs
anything. `--force` reinstalls unconditionally.

**Plan and confirmation.** It first prints the plan (tool, version, category, verification,
destination). On a terminal it asks for confirmation; without one (CI, pipes) it proceeds. `-y`
skips the question and `--dry-run` only previews.

**cosign** is a utility Draugr uses to verify the signatures of other tools and of its own releases
in `self-update`. Without it, signature verification is skipped and the install says so.
`draugr tools install cosign` installs it, pinned by SHA-256. `doctor` reports it without failing
when it is absent, unless the descriptor's `provenance` control needs it.

**Provenance.** The SHA-256 pin is the integrity floor for every release binary. Trivy also
publishes a keyless **cosign** signature over its checksums file; with the `cosign` CLI installed,
Draugr verifies that signature, checking the signing certificate identity and OIDC issuer, and
confirms the archive is listed in the signed checksums. Each line reports what was verified:
`sha256 + cosign verified`, `sha256 verified`, or `sha256 verified;` followed by why the signature
was not checked. If `cosign` is present and verification fails, that tool's install fails.

Semgrep publishes no release binary, so it is installed from PyPI into a virtual environment Draugr
owns (`~/.draugr/venv/semgrep`), with every artifact in the resolved tree matched against a digest
recorded in this build, dependencies included. When `semgrep` is missing, `doctor` suggests
`draugr tools install semgrep`.

### `draugr tools uninstall [tool...]`

Remove tools `draugr tools install` put on this machine: the binary in `~/.draugr/bin`, the Python
or Node environment beside it, and the data Draugr keeps for the tool under `~/.draugr/data`. A
copy installed any other way is left where it is, and the line for it says where it was found.

Each tool's own cache stays unless `--caches` is given: Trivy's and Grype's vulnerability
databases, Nuclei's templates, and the smaller ones Syft, Notation and cosign keep. A tool's settings
are not a cache and stay either way, such as `~/.config/nuclei` and Semgrep's login in `~/.semgrep`.
The caches sit at the tool's default location, or where `TRIVY_CACHE_DIR` or `GRYPE_DB_CACHE_DIR`
moves it, so removing them also empties the cache of any other install of the same tool.
`~/.draugr/feeds` belongs to no tool, and [`draugr feeds`](#draugr-feeds) manages it.

Name the tools to remove, or pass `--all`; with neither, the command is an error.

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Remove every tool Draugr installed |
| `--caches` | `false` | Also remove each tool's own cache |
| `-y, --yes` | `false` | Skip the confirmation prompt |
| `--dry-run` | `false` | Print the plan and exit |

```bash
draugr tools uninstall trivy             # one tool
draugr tools uninstall --all --dry-run   # what removing everything would free
draugr tools uninstall --all --caches    # every tool and its cache
```

```console
$ draugr tools uninstall retire semgrep trivy --dry-run
PLAN
  Tool     Version  Size  Also removes
  retire   5.7.0    10M   node env, data 431K
  semgrep  1.177.0  347M  python env
  trivy    0.74.0   161M

3 tools to remove from /home/you/.draugr, 518M.
The tools' own caches stay (trivy 2.9G). `--caches` removes them too.

(dry run, nothing removed)
```

It asks for confirmation when run interactively, proceeds without asking otherwise, and `--yes`
skips the prompt. It exits non-zero if any named tool was not removed; run it again to retry that
tool. A removed cache refills on the tool's next run.

### `draugr tools list`

Show every tool Draugr knows about: its **category** (scanner or utility), the **controls** it
backs, its pinned version, its source (`draugr tools install`, with the runtime it needs, or
`system PATH`), and its status: `✓` with the version and path when found, `~` when the version
found is not the pin, `✗ not found` otherwise. A version shown as `?` is one the tool did not
report.

```bash
draugr tools list
```

---

## `draugr feeds`

Fetch and inspect the datasets a scan reads from `~/.draugr/feeds`. A scan reads the cache and
fetches a feed only when `--kev` or `--epss` (or `config.exploitability`) says `auto`.

| Feed | Dataset | Read by |
|------|---------|---------|
| `kev` | CISA's Known Exploited Vulnerabilities catalog | [exploitability](saga-schema.md#configexploitability) |
| `epss` | FIRST's EPSS scores | [exploitability](saga-schema.md#configexploitability) |
| `govulndb` | the Go vulnerability database | [govulncheck](../../internal/scanners/govulncheck.md) |

### `draugr feeds update [kev|epss|govulndb]`

Download the feeds into `~/.draugr/feeds`, every feed when none is named. A copy less than a day
old is left alone unless `--force` is given. Refused under `--offline`.

Each feed gets a line saying it is `current (<age> old)`, or `fetching <url>…` followed by the path
and size written. A fetch that fails with a copy already cached keeps that copy, says so and exits
0; with nothing cached, the command stops at that feed and exits non-zero.

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | `false` | Fetch even if the cached copy is current |

```bash
draugr feeds update            # every feed
draugr feeds update epss       # just the daily one
draugr feeds update --force    # refetch regardless of age
```

EPSS is published gzipped and is decompressed on the way in, so the cache holds a CSV the scanner
can read directly. The Go vulnerability database is published as a zip and unpacked into
`~/.draugr/feeds/govulndb`, the directory govulncheck's `-db` reads; an archive whose index is
empty or unreadable is refused and the previous copy kept. Each write is atomic.

**In CI, run this as its own step**, so a feed outage shows in that step rather than inside the
scan.

### `draugr feeds status`

What is cached, how old it is, the digest of each copy, and where each feed comes from.

```
FEED       FETCHED                AGE            SIZE       DIGEST
kev        2026-09-23 22:05Z      6 hours        1.7 MiB    sha256:e4988831e6d3
epss       2026-09-21 04:05Z      3 days (stale) 11.0 MiB   sha256:38015ed64ff2
govulndb   2026-09-24 02:05Z      2 hours        3.2 MiB    sha256:f0645ee8b56c

SOURCES  (cached in /home/you/.draugr/feeds)
  kev        CISA Known Exploited Vulnerabilities catalog · https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  epss       FIRST EPSS scores · https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  govulndb   Go vulnerability database · https://vuln.go.dev/vulndb.zip

epss older than 24 hours. A scan uses it and marks the report stale. Refresh with `draugr feeds update`.
```

A copy is `(stale)` here when it is more than a day old. A stale KEV or EPSS copy does not fail a
scan: it ranks findings on older data, and the report names the age. A stale `govulndb` copy is not
read at all; govulncheck queries `vuln.go.dev` instead, and with `--offline` the control reports an
error. In a scan, `config.exploitability.maxAge` sets the limit for both, while `feeds status` and
`feeds update` always use a day.

### Using the cache in a scan

Set it once in the descriptor under
[`config.exploitability`](saga-schema.md#configexploitability), or pass it per run. `--kev` and
`--epss` accept a path or a keyword:

| Value | Behavior |
|-------|-----------|
| a path | read that file; never touches the cache or the network, the air-gapped route |
| `cache` | read `~/.draugr/feeds`; **never** fetches. Errors if nothing is cached |
| `auto` | read the cache, fetching when it is missing or older than `config.exploitability.maxAge` (default a day) |

With `auto`, a failed fetch falls back to a cached copy and says so. With nothing cached, it is an
error.

`DRAUGR_OFFLINE=1` or `--offline` stops `auto` fetching: it reads the cache, or reports that there
is nothing to read.

**A flag overrides the descriptor only when you type it.** `--epss-threshold 0.5` beats a
descriptor saying `0.1`, although 0.5 is also the flag's default; leaving it off keeps the
descriptor's value.

See [prioritization](../concepts/prioritization.md#exploitability-kev-and-epss) for what the
signals mean and how to choose a threshold.

---

## `draugr config`

Settings for a machine or an organization, read from `draugr.config.yaml`: scanner versions,
control defaults, cache, output and the publish URL. A descriptor cannot set scanner versions,
cache or output settings, so it cannot pin its own scanner version; it can override control
defaults and the publish URL.

```yaml
# draugr.config.yaml
cache:                  # where results are reused between runs, and for how long
  dir: /var/cache/draugr
  ttl: 24h
tools:                  # which build `draugr tools install` fetches
  trivy: { version: "0.69.3" }
controllers:            # merged *underneath* the descriptor's own settings
  sast:
    semgrep:
      config: p/owasp-top-ten
```

| Key | Holds |
|---|---|
| `tools.<name>.version` | the build [`tools install`](#draugr-tools-install-tool) provisions |
| `controllers.<control>.<scanner>` | control defaults, merged underneath the descriptor's `config.controls` |
| `cache.dir`, `cache.ttl`, `cache.readOnly`, `cache.requireDigest` | the `--cache-*` flags. A `ttl` of `0` means the built-in default; `--cache-ttl 0` on the command line means no expiry |
| `output.view`, `output.evidence`, `output.top` | the `--view`, `--evidence` and `--top` flags. A `top` of `0` means the built-in default |
| `output.offerInstall` | whether a scan on a terminal [offers to install](#installing-a-missing-scanner) a missing scanner; unset means it does |
| `publish.apiUrl` | where the `draugr-api` publisher posts, below `$DRAUGR_API_URL` and a `url:` in the descriptor |

A flag typed on the command line always wins over the file. See [caching &
performance](../guides/caching-and-performance.md) for the cache settings.

### Where it comes from

| | |
|---|---|
| `--config <path>` or `DRAUGR_CONFIG` | that file **alone** |
| `./draugr.config.yaml` | this project |
| `~/.draugr/config.yaml` | this machine |

Discovered files are layered, project over home. An explicit one replaces both.

For `draugr scan`, `doctor` and `tools install`, the full order is **component → descriptor → config
→ built-in**, deep-merged, so an override replaces only the keys it names. A scan started through
[`draugr mcp`](#draugr-mcp) does not read the config file.

### Commands

| | |
|---|---|
| `draugr config show` | what is in effect, and **which file each value came from** |
| `draugr config get <key>` | one resolved value |
| `draugr config set <key> <value>` | write a value |
| `draugr config unset <key>` | remove one, pruning anything it empties |
| `draugr config init` | write a commented starter; `--force` replaces an existing file |
| `draugr config validate [path...]` | check the discovered files load, or the files named |

`set`, `unset` and `init` write the file a scan reads: the one `--config` or `DRAUGR_CONFIG` names,
or else `./draugr.config.yaml`, or `~/.draugr/config.yaml` with `--global`. `--global` together
with `--config` or `DRAUGR_CONFIG` is refused, because the global file is not read while either is
set.

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

`show` names the file each value came from.

### If the file breaks

**A command that reads the config refuses to run rather than falling back to the defaults.**

```bash
draugr config validate          # what is wrong, and where
draugr config init --force      # start again from the built-in defaults
```

`set` and `unset` cannot break a file: they edit the parsed document, **so comments survive**, and
parse the result before saving. The document is re-indented as it is written. Draugr does not
repair a file it cannot parse.

### Secrets

Keep credentials out of the file. It is read as written, with no `${{ }}` substitution, and is
meant to be committed. Use the variables under [Environment](#environment) instead.

---

## `draugr controls`

List the security controls Draugr can run, the scanners behind each, and what each checks.
Default scanners are listed first; `*` marks an opt-in scanner and `†` a reachability analyzer, each
explained under the table. `PUBLISHERS` names who publishes each scanner, and `EFFECTS` lists the
scanners that do more than read. [`tools list`](#draugr-tools-list) maps the other way, from each
tool to its controls.

`draugr controls [control]` narrows everything to one control. A name that is not a control says so
and lists the ones that are.

```bash
draugr controls
draugr controls --options          # also: what each scanner accepts in its block
draugr controls sast --options     # just one control
```

| Flag | Default | Description |
|---|---|---|
| `--options` | `false` | List the options each scanner accepts in a descriptor, read from the schemas the gate enforces |

A scanner shown with no options is configured by choosing it, and any other key under its block is
an error.

Enable a control in your descriptor under `config.controls.<name>` (or per component). A control's
scanners are configured under their own keys, `config.controls.<name>.<scanner>`, each with an
optional `enabled` flag plus that scanner's options (e.g. `sast: { gosec: { enabled: true } }`).
See [per-scanner config](saga-schema.md#per-scanner-config).

---

## `draugr mcp`

Serve Draugr to AI coding assistants over the
[Model Context Protocol](https://modelcontextprotocol.io), on stdin/stdout.

```bash
draugr mcp                 # scan asks first only when it does more than read
draugr mcp --scan=ask      # scan asks before every call
draugr mcp --scan=always   # scan never asks
draugr mcp --scan=off      # read-only tools; scan is not offered
```

Each `*.saga.yaml` in the working directory and up to three levels below it is also exposed as an
MCP **resource**, so a client can read the descriptor without a tool call. Discovery runs once at
startup and takes at most 50 files. It skips `node_modules`, `vendor`, `dist`, `build`, `target`
and `__pycache__`, and every hidden directory except `.draugr`.

| Tool | Purpose |
|---|---|
| `list_controls` | Which controls exist, what each checks, which scanner backs it, and the options each scanner accepts |
| `get_saga_schema` | The Saga schema this build enforces |
| `validate_saga` | Validate a descriptor, by `path` or by `content` |
| `propose_saga` | Return the descriptor `draugr init` would write for `path`, a directory under the working directory, with `perDirectory` for `--per-directory`; writes nothing and names any descriptor already there |
| `check_tools` | Report which scanners are installed and what to run if any are missing |
| `feeds_status` | Report whether each feed is cached, with its fetch date, age, size, digest and staleness, and the `draugr feeds update` command to run if any is missing or stale |
| `explain_rule` | What a finding means and how to fix it, from the scan's own report |
| `fix_list` | A report as the things to do about it, most urgent first, each saying how many findings it clears |
| `list_surveyors` | The surveyors this build has and what each discovers |
| `survey` | Discover what an application is made of and return a descriptor for it; writes nothing |
| `diff_reports` | Compare two scans, with `failOnNew` to learn whether a pull-request gate would fail |
| `summarize_report` | Rank an existing `results.sarif` by priority, with accepted findings and their decisions listed apart |
| `scan` | Run a scan and return the verdict, the scope it covered, and where the descriptor's publishers delivered it (not offered with `--scan=off`) |

| Flag | Default | Description |
|---|---|---|
| `--scan` | `effects` | Whether the assistant may start scans, and when you approve one first |

| `--scan` | The `scan` tool |
|---|---|
| `effects` | Asks before a scan in which a planned scanner declares an [effect](saga-schema.md#configalloweffects), `config.dependencyHealth` is enabled, or a publisher other than `file` delivers the report |
| `ask` | Asks before every scan |
| `always` | Never asks, for sandboxes and CI |
| `off` | Is not offered |

Asking needs a client that supports MCP elicitation. A client that cannot prompt is refused and
given the `draugr scan` command instead.

The server speaks MCP on stdin and stdout, so run by hand in a terminal it waits for a client and
prints nothing. A scan started through the server does not read
[`draugr.config.yaml`](#draugr-config). See
[use Draugr from an AI coding assistant](../guides/ai-agents-mcp.md) for client setup.

---

## `draugr self-update`

Update the running `draugr` binary in place to the latest published release (or a specific
`--version`), verified against the release's **SHA-256 checksums** (mandatory) and its keyless
**cosign** signature (when the `cosign` CLI is present). It replaces the binary that is running,
wherever it is on `PATH`. On a terminal it asks for confirmation first; without one it proceeds.
Refused under `--offline`, `--check` included.

| Flag | Default | Description |
|------|---------|-------------|
| `--version` | latest | Target release to install (e.g. `0.16.0` or `v0.16.0`) |
| `--check` | `false` | Report current vs latest available; make no changes |
| `-y, --yes` | `false` | Skip the confirmation prompt |

```bash
draugr self-update            # update to the latest release, asking first on a terminal
draugr self-update --check    # just report current vs latest
draugr self-update --version 0.15.0 -y
```

In CI, install a pinned release; do not run `self-update`.

## `draugr version`

Print the version, commit, build date, and Go version.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit the same fields as JSON (`version`, `commit`, `built`, `go`), for scripts and CI |

```bash
draugr version            # draugr <version> (commit <sha>, built <date>, go<version>)
draugr --version          # the same bytes; -v is the short form
draugr version --json     # an indented JSON object
```

Output goes to stdout in both forms, so `v=$(draugr version --json | jq -r .version)` works.

## `draugr schema`

Print the Saga JSON Schema **this build enforces** (it's embedded in the binary).

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | stdout | Write to this file instead, and print the modeline that references it |
| `--fragment` | `false` | Print the [Saga fragment](../guides/saga-fragments.md) schema instead |

```bash
draugr schema                      # print it
draugr schema -o .saga.schema.json # pin editor validation to this exact build
draugr schema --fragment           # the schema for *.saga-fragment.yaml
```

A fragment has its own schema (no `release:`, no policy); pick it with `--fragment`.

Editors normally fetch the schema from draugr.dev, which needs network access and follows a
published version. A local copy pins validation to the installed Draugr and works offline. See
[editor support](../guides/editor-support.md).

## `draugr completion <shell>`

Generate a shell completion script for `bash`, `zsh`, `fish` or `powershell`.
