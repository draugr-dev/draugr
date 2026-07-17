# Draugr — Architecture (v0 draft)

Status: **draft for discussion**.
Companion: [`plugin-api.md`](plugin-api.md) (interface sketches), [`naming.md`](naming.md).

**Contents:** [1. Model](#1-one-paragraph-model) · [2. Pipeline](#2-pipeline) ·
[3. Data model — the Saga](#3-data-model--the-saga) · [4. Plugin model](#4-plugin-model) ·
[5. SARIF](#5-interchange--sarif-everywhere) ·
[6. Cheap at scale](#6-execution--the-cheap-at-scale-pillar) ·
[7. Component layout](#7-component-layout-proposed-go-module) ·
[8. Deferred](#8-deliberately-deferred) ·
[9. Observability & security](#9-observability--security-standards) ·
[10. Open questions](#10-open-questions)

---

## 1. One-paragraph model

A developer writes a **Saga** (`draugr.saga.yaml`) describing their app's surface —
repos, images, endpoints, infrastructure. Optionally, **Surveyors ("the Ravens")**
discover that surface and write the Saga for them. The **engine** builds an execution
plan (which **Controllers** apply to which components), runs the relevant **Scanners**
concurrently, and normalizes every result to **SARIF**. The **Norn** evaluates results
against policy to produce a pass/fail verdict, and the **Skald** renders audit-ready
evidence. Everything expensive is **cached by content hash** so unchanged components are
never re-scanned.

---

## 2. Pipeline

```
        ┌──────────┐
        │  Survey  │  (optional) Ravens discover surface → Saga fragments
        └────┬─────┘
             ▼
  Describe ─► Plan ─► Scan ─► Aggregate ─► Judge ─► Report ─► Publish
   (Saga)   (jobs) (SARIF)  (per control) (Norn)  (Skald)  (sinks)
```

| Stage | Owner | What happens |
|-------|-------|--------------|
| **Survey** | Surveyors | Enumerate images/endpoints/repos from a cluster, org, or project → Saga fragments. Optional; skipped if the Saga is hand-written. |
| **Describe** | Saga loader | Parse + validate the Saga, resolve env-var substitution and distributed meta-sources into one model. |
| **Plan** | Engine | Expand `(controllers × components)` into a set of scan jobs, honoring scope, enable/skip config, and cache hits. Emit as a plan that can also drive a CI matrix. |
| **Scan** | Controllers → Scanners | Run scanners concurrently via worker pools. Each scanner emits **SARIF**. |
| **Aggregate** | Controllers | Merge + deduplicate a control's scanner outputs into one control result. |
| **Judge** | Norn | Evaluate results against policy → PASS / FAIL / WAIVED per control and overall. |
| **Report** | Reporters (`pkg/report`) + Skald | Render the run: `console` (default), `markdown`, `json`, `sarif`. Skald backs the machine formats (JSON + merged SARIF). |
| **Publish** | Sinks | Write artifacts; push SARIF to GitHub/ADO/GitLab; post status to the control plane. |

---

## 3. Data model — the Saga

The Saga is the source of truth: a *security bill of materials for a running application*.

```yaml
release:
  name: my-app
  version: "${{ RELEASE_VERSION }}"   # env-var substitution

config:                                # global controller config, overridable per component
  controllers:
    sast:      { enabled: true }
    sca:       { enabled: true }
    images:    { enabled: true }
    dast:      { enabled: true }

components:
  - name: backend
    repositories:
      - url: https://github.com/acme/backend.git
        revision: 1.4.0
    images:
      - image: registry.example.com/acme/backend:1.4.0
    hosts:
      - name: api
        url: https://api.acme.com
        type: api
    infrastructure:
      - kind: kubernetes
        ref: prod-cluster
    controllers:                       # per-component overrides
      sast: { sonarqube: { projectKey: acme.backend } }

references:      # links to manual/human controls (threat model, arch diagram, …)
notApplicable:  # declared N/A controls with justification
```

Component surface types (`repositories`, `images`, `hosts`, `infrastructure`) map to
scanner **Target** kinds. A distributed mode (`componentsMetaSources`) lets each service
keep its own Saga fragment next to its source and have the engine assemble them.

---

## 4. Plugin model

Three plugin kinds — **Scanner**, **Controller**, **Surveyor** — delivered through a
layered extension mechanism so the common case is trivial and the hard case is possible.

### Tier 1 — Declarative tool adapters (zero code)
Most scanners are already CLIs or containers, and many already emit SARIF (Trivy, Grype,
Semgrep, ZAP…). A **tool adapter** is a small manifest describing how to invoke a tool
and map its output to SARIF. Covers the majority of integrations and the "bring the tool
you already pay for" case with no compilation.

### Tier 2 — gRPC plugins (real logic)
For scanners/controllers/surveyors that need genuine logic — API clients (Snyk, Mend),
cloud/k8s surveyors, custom aggregation — use out-of-process **gRPC plugins** on the
[HashiCorp go-plugin](https://github.com/hashicorp/go-plugin) pattern (proven by
Terraform/Vault/Nomad). Benefits: language-agnostic, process isolation, a versioned
contract, crash containment.

### Built-ins
A curated set compiles into the core so `draugr` is useful out of the box: scanners
`trivy`/`trivy-fs`/`trivy-config`, `gitleaks`, `semgrep`, `gosec`, and a native
`http-headers`; surveyors `k8s-images` and `github-org-repos`.

### Distribution — "the Hoard"
Plugins are packaged as **OCI artifacts** and pulled from a registry (the Hoard),
**signed with Sigstore/cosign** for provenance. OCI distribution + signing is standard,
registry-native, and dovetails with the supply-chain-security positioning.

---

## 5. Interchange — SARIF everywhere

Every scanner normalizes to **SARIF 2.1.0**. The engine carries an internal superset
(SARIF + Draugr metadata: control, component, target, cache key, waiver) but SARIF is the
lossless core. Consequences:

- Plugins interoperate without N×M adapters.
- Results push straight into GitHub / ADO / GitLab security dashboards.
- Third-party tools already speak it.

---

## 6. Execution & the "cheap at scale" pillar

- **Concurrency:** per-controller worker pools; the whole plan runs as a bounded-parallel
  DAG. Wall-clock ≈ slowest job, not the sum.
- **Content-hash caching:** cache key = `hash(target identity + scanner id + scanner
  version + effective config)`. Target identity is a repo commit, an image *digest*, or a
  normalized endpoint config. Cache hit → skip the scan, reuse the SARIF. Configurable
  TTL/expiry (new CVEs can affect an unchanged artifact, so caching must be explicit and
  time-bounded). This is a first-class, monetizable capability, not an afterthought.
- **Plan-only mode:** emit the execution plan without running — drives CI job matrices and
  complements `draugr doctor` (preflight: are tools/creds/config present?).

---

## 7. Component layout (proposed Go module)

```
draugr/
  cmd/draugr/            # CLI entrypoint (thin: delegates to internal/cli)
  internal/cli/          # Cobra command tree + global flags
  internal/observability/# slog logging + OpenTelemetry tracing
  internal/version/      # build metadata (ldflags-injected)
  pkg/saga/              # descriptor: schema, parse, validate, meta-sources, env subst
  pkg/engine/            # plan, schedule, bounded-concurrency scan, cache, prioritize
  pkg/plugin/            # plugin SDK: interfaces + value types + cache keys
  pkg/tooladapter/       # declarative exec-a-CLI-and-parse-SARIF Scanner runtime
  pkg/sarif/             # SARIF model + superset + merge/dedup
  pkg/norn/              # policy evaluation (thresholds + priority gate)
  pkg/skald/             # JSON + merged-SARIF evidence rendering
  pkg/report/            # multi-format reporting (console, markdown, json, sarif)
  pkg/prioritization/    # exposure × criticality × severity → P1–P4
  pkg/exploit/           # KEV/EPSS exploitability enrichment
  pkg/cache/             # content-hash result cache
  pkg/surveyor/          # Raven framework/registry
  internal/builtins/     # wires the default controllers/scanners/surveyors
  internal/controllers/  # built-in controllers (images, sca, secrets, sast, iac, headers)
  internal/scanners/     # built-in scanners (trivy*, gitleaks, semgrep, gosec, http-headers)
  internal/surveyors/    # built-in surveyors (k8s-images, github-org-repos)
  internal/tools/        # doctor detection + `tools install` provisioning
  internal/selfupdate/   # `self-update` (verified in-place binary update)
  internal/git/          # repository checkout for repo-scanning controls
```

---

## 8. Deliberately deferred

- **Control plane** (`cloud`): history, trends, multi-team governance, RBAC/SSO, evidence
  store. Consumes the same engine + SARIF; not part of the OSS core.
- **Norn policy language:** start with simple declarative thresholds; adopt OPA/Rego when
  policies outgrow them.
- **Waivers/exemptions:** first-class model for accepted risk (with expiry + audit trail).

## 9. Observability & security standards

Draugr is a security product, so its own operational standards must be high.

**CLI framework.** [Cobra](https://github.com/spf13/cobra) — the de-facto Go CLI standard
(kubectl, gh, docker). Consistent help, flags, subcommands, and shell completion.

**Logging.** Structured logging via the standard library's `log/slog`. JSON by default
(machine-readable for log pipelines), `text` for humans; level and format are global
flags (`--log-level`, `--log-format`).

**Tracing/metrics.** [OpenTelemetry](https://opentelemetry.io). Tracing is wired at the
CLI boundary and is opt-in via the standard `OTEL_*` environment variables — a no-op with
zero overhead when unconfigured, OTLP export when an endpoint is set. Metrics across the
scan pipeline follow.

**Secret hygiene (hard rule).** Logs and span attributes must never carry secrets
(tokens, credentials, full request/response bodies). Plugins and scanners redact
sensitive values at the boundary before anything reaches a logger or span.

**Supply-chain & code security (tracked separately, enforced in CI).**
`govulncheck` (known-vuln deps), `gosec` + `golangci-lint` (static analysis), pinned
dependencies + `go.sum`, Dependabot, SBOM generation, and signed releases (Sigstore/cosign)
with provenance. Draugr should meet the bar it holds others to.

## 10. Open questions

- gRPC plugin contract versioning + compatibility policy.
- Cache backend abstraction (local dir → shared/remote for CI and the control plane).
- How much SARIF superset is needed for compliance evidence vs. a separate schema.
- Consuming VEX to suppress non-exploitable CVEs (false-positive reduction).
