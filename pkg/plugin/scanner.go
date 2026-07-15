package plugin

import (
	"context"
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Scanner wraps a single security tool and runs one kind of scan. It is the atomic unit
// of work. Implementations must be side-effect-free with respect to the target and must
// honor ctx cancellation. Output is normalized to SARIF.
type Scanner interface {
	Info() ScannerInfo
	Scan(ctx context.Context, target Target, cfg Config) (sarif.Report, error)
}

// CacheVersioner is an optional interface a Scanner may implement to contribute a
// tool/data version to its cache key — so that an update to the underlying tool or its
// data (e.g. a vulnerability database) invalidates cached results, not just the TTL. The
// engine calls CacheVersion only when caching is enabled, and folds a non-empty return
// into the cache key. It is resolved lazily; implementations should memoize any probe and
// return "" when the version can't be determined (the key then falls back to Info().Version).
// Unlike Info(), CacheVersion may perform I/O.
type CacheVersioner interface {
	CacheVersion(ctx context.Context) string
}

// Prewarmer is an optional interface a Scanner may implement to warm shared, expensive state
// once before a run's concurrent fan-out — e.g. downloading a vulnerability database — so that
// many parallel scans don't each cold-start it (a thundering herd). The engine calls Prewarm
// once per distinct scanner, before scans start; a returned error is best-effort (logged, not
// fatal — the scan will surface any real problem). Implementations should memoize.
type Prewarmer interface {
	Prewarm(ctx context.Context) error
}

// ScannerInfo describes a scanner and its capabilities.
type ScannerInfo struct {
	// Name is the scanner identifier, e.g. "trivy".
	Name string
	// Binary is the external executable the scanner shells out to, e.g. "trivy". Empty for
	// scanners that need no external tool. Used by `draugr doctor` to check availability.
	Binary string
	// Version is the scanner/plugin version; it participates in the cache key.
	Version string
	// Controls are the security controls this scanner can serve, e.g. ["images"].
	Controls []string
	// TargetKinds are the target kinds this scanner accepts.
	TargetKinds []TargetKind
	// ConfigSchema is a JSON Schema for Config; it drives validation and the config wizard.
	ConfigSchema json.RawMessage
}
