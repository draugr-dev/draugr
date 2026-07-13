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
| `--cache-dir` | — | Enable content-hash caching in this directory |
| `--cache-ttl` | `24h` | Cache entry lifetime (`0` = no expiry) |

```bash
draugr scan draugr.saga.yaml
draugr scan draugr.saga.yaml -o out/ --fail-on warning
draugr scan draugr.saga.yaml --min-priority P2        # focus on what matters now
draugr scan draugr.saga.yaml --fail-on-priority P1    # also block on P1 findings
draugr scan draugr.saga.yaml --cache-dir .draugr-cache
```

**Priority** requires components to declare `exposure`/`criticality` (see the
[Saga reference](saga-reference.md)); Draugr ranks each finding P1–P4 from its severity and
the component's risk. See [concepts](concepts.md#prioritization-what-to-fix-first).

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

## `draugr version`

Print the version, commit, build date, and Go version.

## `draugr completion <shell>`

Generate a shell completion script (bash, zsh, fish, powershell).
