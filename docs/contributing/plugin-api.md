# Draugr, Plugin API

Reference for the plugin interfaces as implemented in [`pkg/plugin`](../../pkg/plugin) (and the
`Reporter` in [`pkg/report`](../../pkg/report)). See [`architecture.md`](architecture.md) for context.

The plugin kinds, **Scanner**, **Controller**, **Surveyor**, **Reporter**, **Publisher**, share a
small set of value types. [Adding a plugin](#adding-a-plugin) covers how a new one is added.

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
    TargetKubernetes TargetKind = "kubernetes"
)

type RepositoryTarget struct { URL, Revision string; Paths []string }
type ImageTarget      struct { Ref, Digest string }  // digest drives Identity() (cache key)
type HostTarget       struct { Name, URL, Type string }      // type: browser | api
type KubernetesTarget struct { Ref string }                  // e.g. prod-cluster

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

## Surveyor

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

Renders a scan result in one format. Lives in [`pkg/report`](../../pkg/report); `draugr scan
--format` selects one. Built-in formats: `console` (default), `markdown`, `html`, `junit`,
`json`, `sarif`, and `template` (a user-supplied Go `text/template`).

```go
type Reporter interface {
    Format() string                      // "console", "markdown", "html", "junit", "json", "sarif"
    Render(w io.Writer, d Data) error
}

// Data is everything a reporter needs to render a scan.
type Data struct {
    Release     saga.Release
    Run         engine.Result
    Verdict     norn.Result
    MinPriority string
}

// report.Build renders Data in a format and returns it as an Artifact (bytes + filename +
// content type), the unit a Publisher delivers.
type Artifact struct {
    Format      string // e.g. "sarif"
    Filename    string // e.g. "results.sarif"
    ContentType string // e.g. "application/sarif+json"
    Bytes       []byte
}
```

## Publisher

Delivers rendered reports to a destination, the "where" of reporting, separate from the Reporter
(the "what"). Lives in [`pkg/publish`](../../pkg/publish); configured from the Saga's
`config.publishers`. Built-in kinds: `file`, `github` (uploads the SARIF report to code scanning),
and `github-pr-comment` (posts the markdown report as a sticky PR comment). Every rendered report is
delivered to every configured publisher, so a publisher takes only the artifacts it needs.

```go
type Publisher interface {
    Kind() string                                          // config selector, e.g. "file"
    Publish(ctx context.Context, artifacts []report.Artifact) error
}
```

## Adding a plugin

The `draugr` binary runs the scanners, controllers and surveyors that
[`internal/builtins`](../../internal/builtins/builtins.go) registers, and no others. It loads
nothing at runtime, so there is no out-of-process or gRPC plugin, no plugin manifest and no plugin
directory to drop one into. Another tool's findings reach a scan in one of two ways.

- **A pull request adding it in-tree.** Implement the interface under `internal/scanners`,
  `internal/controllers` or `internal/surveyors` and register it in `builtins.go`.
  [Extending Draugr](extending/README.md) has a guide for each kind, starting with a table for
  picking the right one.
- **A SARIF file, with no code.** A component's
  [`imports`](../reference/saga-schema.md#componentsimports) reads a SARIF 2.1.0 file that another
  tool wrote into one of Draugr's controls, where its findings are prioritized and gated with the
  rest. [Import another scanner's SARIF](../guides/importing-sarif.md) walks through it.

### Tool adapter

[`pkg/tooladapter`](../../pkg/tooladapter/tooladapter.go) shortens the in-tree route for a scanner
that runs a command-line tool. `tooladapter.Config` takes the tool's `ScannerInfo` fields and a Go
function that builds the command line for a target, and `tooladapter.New` returns a `Scanner` that
runs the command and decodes its stdout as SARIF. A tool that reports in its own format supplies a
`Parse` function instead. Optional hooks (`Run`, `CacheVersion`, `Prewarm`, `DataState`, `Refine`)
are documented on `Config`. `trivy` and `grype` are built this way, as is the image half of
`trivy-license`.

## Design rules

- **SARIF is the only result currency.** A scanner whose tool doesn't emit SARIF maps its output
  to SARIF at the boundary.
- **Config is schema-validated** up front; the JSON Schema also powers the config wizard.
- **Determinism & cacheability:** given the same target identity + version + config, a
  scanner should produce equivalent findings so cache keys are meaningful.
- **Least privilege:** plugins declare the credentials/network they need; nothing implicit.
