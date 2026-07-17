# Draugr — Plugin API

Reference for the plugin interfaces as implemented in [`pkg/plugin`](../pkg/plugin) (and the
`Reporter` in [`pkg/report`](../pkg/report)). See [`ARCHITECTURE.md`](ARCHITECTURE.md) for context.

The plugin kinds — **Scanner**, **Controller**, **Surveyor**, **Reporter** — share a small set
of value types. Scanners are transported in-process (built-ins) or declaratively (tool adapters
that satisfy the Scanner contract at runtime); an out-of-process gRPC transport is planned.

## Shared types

```go
// Target is something a scanner can act on. Identity is the stable cache-key value.
type Target interface {
    Kind() TargetKind
    Identity() string
}

type TargetKind string
const (
    TargetRepository TargetKind = "repository"
    TargetImage      TargetKind = "image"
    TargetHost       TargetKind = "host"
    TargetInfra      TargetKind = "infrastructure"
)

type RepositoryTarget struct { URL, Revision string; Paths []string }
type ImageTarget      struct { Ref, Digest string }  // digest drives Identity() (cache key)
type HostTarget       struct { Name, URL, Type string }      // type: browser | api
type InfraTarget      struct { Platform, Ref string }        // e.g. kubernetes / prod-cluster

// ImageTarget.PinnedRef() returns the digest-pinned reference (repo:tag@sha256:…) a scanner
// should pull, so the bytes scanned match the digest the result is cached under.

// Config is validated against the plugin's declared JSON schema before use.
type Config map[string]any

// CacheKey = ComputeCacheKey(scanner name, version, target kind + Identity(), sorted config).
type CacheKey string
```

## Scanner

Wraps a single tool; the atomic unit of work. Emits SARIF.

```go
type Scanner interface {
    Info() ScannerInfo
    // Scan runs the tool against target and returns a SARIF report.
    // Implementations must be side-effect-free w.r.t. the target and honor ctx cancellation.
    Scan(ctx context.Context, target Target, cfg Config) (sarif.Report, error)
}

type ScannerInfo struct {
    Name         string          // e.g. "trivy"
    Binary       string          // external executable to check on PATH (e.g. "trivy"); "" if none
    Version      string          // scanner/plugin version (part of the cache key)
    Controls     []string        // controls it can serve, e.g. ["images"]
    TargetKinds  []TargetKind    // targets it accepts
    ConfigSchema json.RawMessage // JSON Schema for Config (drives the config wizard)
}

// A Scanner may optionally implement these; the engine uses them when present.
type CacheVersioner interface {
    // CacheVersion contributes a tool/data version to the cache key (may do I/O, unlike Info),
    // so a tool or vuln-DB update invalidates cached results. "" = no contribution.
    CacheVersion(ctx context.Context) string
}
type Prewarmer interface {
    // Prewarm warms shared tool state once before the concurrent fan-out (e.g. download the
    // Trivy vuln DB). Best-effort.
    Prewarm(ctx context.Context) error
}
```

## Controller

Orchestrates scanners for one security control; plans work and aggregates results.

```go
type Controller interface {
    Info() ControllerInfo
    // Plan expands a component (or the project) into scan jobs for this control.
    Plan(saga saga.Model, comp *saga.Component) ([]ScanJob, error)
    // Aggregate merges + deduplicates this control's scanner outputs into one result.
    Aggregate(results []sarif.Report) (ControlResult, error)
}

type ControllerInfo struct {
    Name            string   // e.g. "images", "sast", "sca"
    Scope           Scope    // project | component
    Summary         string   // one-line purpose, shown by `draugr controls`
    DefaultScanners []string // scanner(s) run by default (opt-in extras via config)
}
type Scope string
const ( ScopeProject Scope = "project"; ScopeComponent Scope = "component" )

type ScanJob struct {
    Scanner  string   // scanner to run
    Target   Target
    Config   Config
    CacheKey CacheKey // usually left empty; the engine computes the effective key
}

type ControlResult struct {
    Control string
    Report  sarif.Report   // merged, deduplicated
    Summary Summary        // counts by severity, for the Norn
}

type Summary struct { Errors, Warnings, Notes int }
```

## Surveyor ("Raven")

Discovers surface and contributes Saga fragments so the descriptor writes itself.

```go
type Surveyor interface {
    Info() SurveyorInfo
    // Survey inspects a scope and returns a Saga fragment (components/targets it found).
    Survey(ctx context.Context, scope SurveyScope) (saga.Fragment, error)
}

type SurveyorInfo struct {
    Name         string          // e.g. "k8s-images", "github-org-repos"
    Provides     []TargetKind    // what it can discover
    ConfigSchema json.RawMessage
}

// SurveyScope examples: a kube context + namespace, a GitHub org, an ADO project.
type SurveyScope struct { Kind string; Ref string; Config Config }
```

## Reporter

Renders a scan result in one format. Lives in [`pkg/report`](../pkg/report); `draugr scan
--format` selects one. Built-in formats: `console` (default), `markdown`, `json`, `sarif`.

```go
type Reporter interface {
    Format() string                      // "console", "markdown", "json", "sarif"
    Render(w io.Writer, d Data) error
}

// Data is everything a reporter needs to render a scan.
type Data struct {
    Release     saga.Release
    Run         engine.Result
    Verdict     norn.Result
    MinPriority string
}
```

## Transport

- **Built-in:** implement the interface directly, compiled into the core.
- **gRPC (go-plugin):** the same interfaces exposed over a versioned gRPC contract;
  the plugin runs as a subprocess. Language-agnostic, isolated, crash-contained.
- **Tool adapter (declarative):** a manifest (invoke this CLI/container with these args;
  its stdout is SARIF, or map fields X→SARIF) that the runtime presents as a `Scanner`.
  No code; covers the majority of existing tools and BYO-tool.

## Design rules

- **SARIF is the only result currency.** Adapters/plugins that don't emit SARIF natively
  must map to it at the boundary.
- **Config is schema-validated** up front; the JSON Schema also powers the config wizard.
- **Determinism & cacheability:** given the same target identity + version + config, a
  scanner should produce equivalent findings so cache keys are meaningful.
- **Least privilege:** plugins declare the credentials/network they need; nothing implicit.
