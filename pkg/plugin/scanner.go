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
	// AlsoRequires names further executables that must be present for the scanner to work.
	//
	// Some tools shell out in turn: kube-bench's CIS policy checks are scripts that invoke
	// kubectl, so a machine with kube-bench and no kubectl fails at scan time rather than at
	// `draugr doctor`. Declaring the whole requirement is what lets the preflight check be
	// worth running.
	AlsoRequires []string
	// Version is the scanner/plugin version; it participates in the cache key.
	Version string
	// Controls are the security controls this scanner can serve, e.g. ["images"].
	Controls []string
	// TargetKinds are the target kinds this scanner accepts.
	TargetKinds []TargetKind
	// ConfigSchema is a JSON Schema for Config; it drives validation and the config wizard.
	ConfigSchema json.RawMessage
	// Effects declare what this scanner does to a target beyond reading it. Empty — the common
	// case — means it reads an artifact and nothing else.
	//
	// Draugr surfaces these before a scan runs and records them in the report afterwards, and
	// refuses to run a scanner whose effects have not been acknowledged. A scanner that omits an
	// effect it has is worse than one that overstates: the point is that nothing consequential
	// happens to a target without the operator having agreed to it.
	Effects []Effect
}

// EffectKind categorises what a scanner does beyond reading its target.
type EffectKind string

// The kinds of effect a scanner can declare.
//
// The distinction that matters is the **target**. Fetching a vulnerability database from a
// vendor is a network call, but it is not a consequence for the thing being scanned, and it is
// not an effect. Sending traffic to the customer's endpoint is.
const (
	// EffectNetwork sends traffic to the target rather than reading an artifact. Probing a host
	// you do not own is unlawful in many jurisdictions, which is why it is worth stating even
	// though it changes nothing.
	EffectNetwork EffectKind = "network"
	// EffectMutate creates or changes something that outlives the scan.
	EffectMutate EffectKind = "mutate"
	// EffectPrivilege needs access beyond what reading the target requires.
	EffectPrivilege EffectKind = "privilege"
)

// RequiresConsent reports whether an effect must be acknowledged before a scanner runs.
//
// Mutating a target or asking for elevated access is a decision someone should make on purpose.
// Network traffic is declared and recorded but not gated: the controls that send it exist to
// send it, and demanding consent per run for the thing the control is *for* trains people to
// agree without reading. The obligation it carries — that you are entitled to probe the host —
// is set out in the scope and disclaimer.
func (k EffectKind) RequiresConsent() bool {
	return k == EffectMutate || k == EffectPrivilege
}

// Effect is something a scanner does to a target beyond reading it.
type Effect struct {
	Kind EffectKind
	// Detail is one line, addressed to whoever has to approve it: what will happen, in terms of
	// the target rather than the implementation.
	Detail string
}
