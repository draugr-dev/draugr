# CLI reference

All commands accept these **global flags**:

| Flag | Default | Description |
|------|---------|-------------|
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | `json` | `json` or `text` |

Telemetry (traces/metrics) is opt-in via standard `OTEL_*` environment variables; it is a
no-op when unset.

---

## `draugr scan <saga.yaml>`

Load a Saga, run the applicable controls, and produce a pass/fail verdict. Prints the JSON
report to stdout. **Exits non-zero when the verdict is `fail`.**

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

```bash
draugr scan draugr.saga.yaml
draugr scan draugr.saga.yaml -o out/ --fail-on warning
draugr scan draugr.saga.yaml --min-priority P2        # focus on what matters now
draugr scan draugr.saga.yaml --fail-on-priority P1    # also block on P1 findings
draugr scan draugr.saga.yaml --cache-dir .draugr-cache
draugr scan draugr.saga.yaml -j 4                      # cap parallelism (or -j 1 for serial)
```

**Tuning parallelism (`-j`/`--jobs`).** By default Draugr runs up to one scan job per CPU. But
scanners like Trivy and Semgrep are themselves multi-threaded, so on a busy or small machine
that default can oversubscribe the box and *slow the run down* — dial it down with `-j`. On a
big CI runner you can dial it up. `-j 1` runs serially (deterministic output; handy for
debugging). The run's JSON `stats` reports the effective `concurrency` alongside `jobs` (total
jobs), `scans`, `cacheHits`, and `deduped`, so you can see the effect and tune from evidence.

**Priority** requires components to declare `exposure`/`criticality` (see the
[Saga reference](saga-reference.md)); Draugr ranks each finding P1–P4 from its severity and
the component's risk. See [concepts](concepts.md#prioritization-what-to-fix-first).

**Exploitability (`--kev`/`--epss`)** raises a finding's severity by real-world signals — a
CVE on CISA's [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(confirmed exploited) becomes critical; a CVE at/above the [EPSS](https://www.first.org/epss/)
threshold (predicted likely) is bumped one band. Both are optional, offline (bring your own
downloaded file), and only affect findings whose rule id is a CVE.

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

## `draugr validate <saga.yaml>`

Parse a Saga, resolve `${{ VAR }}` references, and check it against the schema — **without
running any scanners**. Fast and dependency-free, so it fits a pre-commit hook, a CI lint
step, or an editor. **Exits non-zero when the descriptor is invalid.**

```bash
draugr validate draugr.saga.yaml
```

---

## `draugr doctor [saga.yaml]`

Preflight the environment: report which external scanner tools are **present, missing, or of
what version**, with an install hint for each — so a missing tool is caught up front instead
of failing mid-scan. Given a Saga, it first **validates the descriptor**, then checks only the
tools its enabled controls need (`trivy`, `gitleaks`, `semgrep`, plus `git` for repo scans);
without one, it checks them all. **Exits non-zero when the descriptor is invalid or a required
tool is missing**, so it gates CI: `draugr doctor saga.yaml && draugr scan saga.yaml`.

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

```bash
draugr tools install            # plan → confirm → install everything, into ~/.draugr/bin
draugr tools install trivy      # just one
draugr tools install --dry-run  # preview the plan, change nothing
draugr tools install -y         # non-interactive
```

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

Show every scanner Draugr knows about: its pinned version, how it's obtained (managed install /
pipx / system), and whether it's currently found (with path + version).

```bash
draugr tools list
```

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

## `draugr completion <shell>`

Generate a shell completion script (bash, zsh, fish, powershell).
