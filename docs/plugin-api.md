# Draugr — Plugin API (v0 sketch)

Status: **draft**. Illustrative Go signatures to anchor discussion — not final, not yet
compiled. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for context.

The three plugin kinds — **Scanner**, **Controller**, **Surveyor** — share a small set of
value types and are transported either in-process (built-ins), via gRPC (go-plugin), or
declaratively (tool adapters that satisfy the Scanner contract at runtime).

## Shared types

```go
// Target is something a scanner can act on. One of the concrete kinds below.
type Target interface{ Kind() TargetKind }

type TargetKind string
const (
    TargetRepository TargetKind = "repository"
    TargetImage      TargetKind = "image"
    TargetHost       TargetKind = "host"
    TargetInfra      TargetKind = "infrastructure"
)

type RepositoryTarget struct { URL, Revision string; Paths []string }
type ImageTarget      struct { Ref, Digest string }          // digest drives the cache key
type HostTarget       struct { Name, URL, Type string }      // type: api | web
type InfraTarget      struct { Kind, Ref string }            // e.g. kubernetes / prod-cluster

// Config is validated against the plugin's declared JSON schema before use.
type Config map[string]any

// CacheKey = hash(target identity + scanner id + version + effective config).
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
    Version      string          // scanner/plugin version (part of the cache key)
    Controls     []string        // controls it can serve, e.g. ["images"]
    TargetKinds  []TargetKind    // targets it accepts
    ConfigSchema json.RawMessage // JSON Schema for Config (drives the config wizard)
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
    Name  string          // e.g. "images", "sast", "opensource"
    Scope Scope           // project | component
}
type Scope string
const ( ScopeProject Scope = "project"; ScopeComponent Scope = "component" )

type ScanJob struct {
    Scanner  string   // scanner to run
    Target   Target
    Config   Config
    CacheKey CacheKey
}

type ControlResult struct {
    Control  string
    Report   sarif.Report   // merged, deduplicated
    Findings Summary        // counts by severity, for the Norn
}
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
