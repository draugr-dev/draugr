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
