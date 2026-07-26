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

**Seeing what Draugr is doing.** `--log-level debug` narrates the run: what was planned, the
**exact command** handed to each scanner with its working directory, duration and exit code,
cache hits, findings per control, and aggregation.

```console
$ draugr scan . --log-level debug
DEBUG planned job control=sca scanner=trivy-fs target_kind=repository
DEBUG ran scanner tool tool=trivy argv="trivy fs --quiet --scanners vuln --format sarif /tmp/…" duration=43ms
DEBUG scan complete control=sca scanner=trivy-fs findings=0 duration=50ms
```

`--log-level trace` adds what the **scanners themselves** print. Draugr captures a tool's stderr
and normally only summarises it in an error; trace relays it verbatim, which is usually where the
real explanation is. Verbose by design — reach for it when debug hasn't answered the question.

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
```

For an instant scan with no file at all, use zero-config `draugr scan .` (below).

## `draugr scan [saga.yaml | dir]`

Load a Saga, run the applicable controls, and produce a pass/fail verdict. Prints a
human-readable **console** summary to stdout by default (`--format` for other formats).
**Exits non-zero when the verdict is `fail`.**

**Zero-config.** Point `scan` at a **directory** (or omit the argument to use the current one)
and Draugr scans that repository with `sca`, `secrets`, `sast`, and `iac` — no Saga required.
A one-line note is printed to stderr so machine formats on stdout stay clean. A Saga **file**
argument runs exactly as before.

```bash
draugr scan            # zero-config: scan the current repo
draugr scan ./service  # zero-config: scan another repo directory
draugr scan draugr.saga.yaml   # full control from a descriptor
```

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | — | Directory to write `report.json` and `results.sarif` |
| `--fail-on` | `error` | Severity that fails the gate: `error`, `warning`, `note` |
| `--fail-on-priority` | — | Also fail the gate on any finding at or above this priority (`P1`–`P4`) |
| `--min-priority` | — | List findings at or above this priority band (`P1`–`P4`) |
| `--kev` | — | CISA KEV catalog JSON; a CVE on it is escalated to critical |
| `--epss` | — | FIRST EPSS scores CSV; a CVE at/above `--epss-threshold` is bumped one band |
| `--epss-threshold` | `0.5` | EPSS probability (0–1) that triggers a severity bump |
| `--cache-dir` | — | Enable content-hash caching in this directory |
| `--cache-ttl` | `24h` | Cache entry lifetime (`0` = no expiry) |
| `-j, --jobs` | `0` (auto) | Max scan jobs to run in parallel (`0` = one per CPU); reported as `stats.concurrency` |
| `--format` | `console` | stdout report format: `console`, `markdown`, `html`, `junit`, `json`, `sarif`, `template` |
| `--template` | — | inline Go `text/template` (with `--format template`) |
| `--template-file` | — | Go `text/template` file (with `--format template`) |
| `--no-publish` | `false` | Skip the Saga's configured publishers (still writes `-o` artifacts and stdout) |
| `--top` | `10` | Console: max findings to list in the "Fix first" table (`0` = all) |
| `--no-tips` | `false` | Suppress the console's contextual tips (also `DRAUGR_NO_TIPS`) |
| `--compact` | `false` | Strip indentation and rule documentation from `json`/`sarif` output. For a consumer that acts on the report rather than reads it — see [machine-readable output](../guides/reports-and-publishers.md#compact-output-for-tools-and-agents) |

```bash
draugr scan draugr.saga.yaml
draugr scan draugr.saga.yaml -o out/ --fail-on warning
draugr scan draugr.saga.yaml --min-priority P2        # focus on what matters now
draugr scan draugr.saga.yaml --fail-on-priority P1    # also block on P1 findings
draugr scan draugr.saga.yaml --cache-dir .draugr-cache
draugr scan draugr.saga.yaml -j 4                      # cap parallelism (or -j 1 for serial)
draugr scan draugr.saga.yaml --format markdown        # portable report (MR comment, wiki)
draugr scan draugr.saga.yaml --format html > report.html   # shareable browser report
draugr scan draugr.saga.yaml --format junit > report.xml   # CI test panel
draugr scan draugr.saga.yaml --format json | jq .     # machine-readable
draugr scan draugr.saga.yaml --format template --template '{{.Verdict}}: P1={{.Priorities.P1}}'
```

**Output formats (`--format`).** stdout defaults to a human **console** summary (verdict,
priority/severity counts, "fix first"). `markdown` produces a portable report for MR comments
or wikis; `html` is a self-contained, browser-viewable report you can publish as a build
artifact; `junit` emits JUnit XML so CI systems (GitLab, Jenkins, Azure DevOps…) surface
findings in their test-results panel; `json` and `sarif` are the machine formats; `template`
renders your own Go `text/template` (see [`config.reports`](saga-schema.md#configreports-and-configpublishers)
for the available fields). Regardless of `--format`, `--output <dir>` always writes both
`report.json` and `results.sarif` for CI/code-scanning. To render **multiple** formats and deliver
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

---

## `draugr diff <base.sarif> <head.sarif>`

Compare two scans and classify every finding as **new**, **fixed**, or **unchanged** — the
security delta of a change, typically a PR's head vs its base branch. Inputs are the
`results.sarif` files that [`draugr scan -o`](#draugr-scan-sagayaml) writes (SARIF is the
complete, structured result set; the JSON summary can be trimmed by `--min-priority`).

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `console` | output format: `console`, `markdown`, `json` |
| `--fail-on-new` | — | fail if a **new** finding is at or above this severity: `error`, `warning`, `note` |
| `--fail-on-new-priority` | — | fail if a **new** finding is at or above this priority (`P1`–`P4`) |
| `--publish` | `false` | post the diff as a sticky pull-request comment (`github-pr-comment` publisher; uses `$GITHUB_TOKEN` in CI, no-ops off a PR) |

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

**Finding identity.** Findings are matched on `(tool, rule, file, message)` — deliberately
ignoring the line number (which drifts as code moves) and the severity level (a re-scored finding
is still the same issue), so genuinely-carried-over findings aren't reported as fixed + new.

---

## `draugr survey`

Run discovery surveyors ("the Ravens") and materialize the results into a Saga. At least
one surveyor must be selected.

| Flag | Default | Description |
|------|---------|-------------|
| `--k8s-images` | `false` | Discover container images in a Kubernetes cluster |
| `--k8s-namespace` | all | Namespace for `--k8s-images` |
| `--github-org` | — | Discover repositories in this GitHub org |
| `-o, --output` | stdout | Write the Saga here |
| `--merge` | `false` | Merge into the existing Saga at `--output` |
| `--name` | — | Release name for a newly created Saga |
| `--version` | `0.0.0` | Release version for a newly created Saga |

Auth: the GitHub surveyor uses `GITHUB_TOKEN` (or a token in scope config); the Kubernetes
surveyor uses your ambient kubeconfig (`KUBECONFIG` / `~/.kube/config` / in-cluster).

```bash
draugr survey --github-org my-org -o draugr.saga.yaml
draugr survey --k8s-images --k8s-namespace prod --merge -o draugr.saga.yaml
```

When scoped to a specific namespace, `--k8s-images` also **proposes each component's
`exposure`** from topology (Ingress/external Service → `public`, NetworkPolicy → `restricted`,
else `internal`) — review it, then set `criticality` with [`draugr classify`](#draugr-classify-sagayaml).

---

## `draugr classify <saga.yaml>`

A guided wizard that sets each component's **`exposure`** and **`criticality`** — the two
inputs to finding prioritization — and writes them back into the Saga (preserving comments and
formatting). It asks a few questions per component and derives the labels; by default it only
asks about unclassified components.

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | `false` | Re-classify every component, not just unclassified ones |

```bash
draugr classify draugr.saga.yaml
```

---

## `draugr validate [saga.yaml | glob ...]`

Parse each Saga, resolve `${{ VAR }}` references, and check it against the schema — without
running any scanners. Fast and dependency-free, so it suits a pre-commit hook, a CI lint step, or
an editor. **Exits non-zero if any file is invalid.**

Accepts paths and globs, and with no arguments discovers every `*.saga.yaml` (and `.yml`) beneath
the current directory — useful in a repo holding one Saga per service. `.git`, `node_modules`,
`vendor` and `dist` are skipped.

```bash
draugr validate                          # every Saga in the repo
draugr validate draugr.saga.yaml         # one file
draugr validate 'services/*/*.saga.yaml' # a glob (quote it, so the shell doesn't expand it first)
```

Each file is reported on its own line, so one failure doesn't hide the rest:

```
✓ draugr.saga.yaml is valid
✗ svc-b/web.saga.yaml
    unknown field "componnets" in the top level — check the spelling, or see …
```

A pattern that matches nothing is an error rather than a silent success — otherwise a typo'd
pattern would make a CI lint step quietly pass.


## `draugr doctor [saga.yaml]`

Preflight the environment: report which external scanner tools are **present, missing, or of
what version**, with an install hint for each — so a missing tool is caught up front instead
of failing mid-scan. Given a Saga, it first **validates the descriptor**, then checks only the
tools its enabled controls need (`trivy`, `gitleaks`, `semgrep`, plus `git` for repo scans, and
`gosec` only when a component opts into it); without one, it checks them all. Optional tools that
aren't selected don't count as missing. **Exits non-zero when the descriptor is invalid or a
required tool is missing**, so it gates CI: `draugr doctor saga.yaml && draugr scan saga.yaml`.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit the report as JSON instead of a table |
| `--offline` | `false` | Skip the check for a newer draugr release (also `DRAUGR_NO_UPDATE_CHECK=1`) |

```bash
draugr doctor                       # check every tool Draugr can use
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

```bash
draugr tools install            # plan → confirm → install everything, into ~/.draugr/bin
draugr tools install trivy      # just one
draugr tools install --dry-run  # preview the plan, change nothing
draugr tools install -y         # non-interactive
```

**Already-installed tools are skipped.** Re-running is cheap: a tool already present at the
pinned build is left alone (`• trivy 0.69.3 already installed → …`) instead of being downloaded
and verified again — which matters in CI, where provisioning runs on every job. "Already present"
means the exact bytes Draugr installed: it compares the binary's checksum against what it
recorded, so a **modified binary is replaced**, not accepted. A changed pin also reinstalls.
Use `--force` to reinstall unconditionally.

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

Semgrep ships as a Python package, not a standalone binary, so `tools install` prints the
pinned `pipx install semgrep==<version>` command rather than downloading it. `git` is expected
from your system.

### `draugr tools list`

Show every tool Draugr knows about: its **category** (scanner/utility), the **controls** it
backs, its pinned version, how it's obtained (managed install / pipx / system), and whether
it's currently found (with path + version).

```bash
draugr tools list
```

---

## `draugr controls`

List the security controls Draugr can run — what each checks, its scope, and which scanner(s)
implement it (default, plus any opt-in alternatives marked `*`). The companion to
`tools list`: `controls` maps **control → scanners** ("what runs this check"), while `tools
list` maps **tool → controls** ("why this tool matters").

```bash
draugr controls
```

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
draugr mcp --scan=ask      # additionally expose scan, approving each call
draugr mcp --scan=always   # additionally expose scan, without prompting
```

Every `*.saga.yaml` found within three directories of the working directory is also exposed as
an MCP **resource**, so a client can read the descriptor without a tool call.

| Tool | Purpose |
|---|---|
| `list_controls` | Which controls exist, what each checks, which scanner backs it |
| `get_saga_schema` | The Saga schema this build enforces |
| `validate_saga` | Validate a descriptor, by `path` or by `content` |
| `summarize_report` | Rank an existing `results.sarif` by priority |
| `scan` | Run a scan and return the verdict (requires `--scan=ask` or `--scan=always`) |

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
draugr version --json     # {"version":"0.31.1","commit":"30862ef","built":"…","go":"go1.26.5"}
```

Output goes to stdout in both forms, so `v=$(draugr version --json | jq -r .version)` works.

## `draugr schema`

Print the Saga JSON Schema **this build enforces** (it's embedded in the binary).

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | — | Write to this file instead of stdout |

```bash
draugr schema                      # print it
draugr schema -o .saga.schema.json # pin editor validation to this exact build
```

Editors normally fetch the schema from draugr.dev, which needs network access and follows a
published version. A local copy pins validation to the Draugr you actually have, and works
offline — see [editor support](saga-schema.md#editor-support-autocomplete-hover-docs-validation).

## `draugr completion <shell>`

Generate a shell completion script (bash, zsh, fish, powershell).
