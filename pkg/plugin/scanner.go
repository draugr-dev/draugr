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

// OriginDraugr marks a scanner whose detection logic is Draugr's own rather than an external
// tool's. It is the value the registry stamps on every built-in native scanner.
const OriginDraugr = "draugr"

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
	// Origin names who publishes the tool this scanner runs — the upstream project, not the
	// scanner's author. "aquasecurity" for Trivy and kube-bench, "projectdiscovery" for Nuclei,
	// "draugr" for a scanner whose detection logic is Draugr's own.
	//
	// Read rather than declared, when it can be: OriginDraugr is stamped by the registry for
	// built-ins, and a plugin's Origin is stamped by whatever loaded it. A scanner that could
	// name its own origin could claim one, and the whole value of the field is that a reader can
	// trust it — "which of these is a third party executing on my machine" is a supply-chain
	// question, and an answer the subject supplies is not an answer.
	Origin string
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
// not an effect. Sending traffic to the customer's endpoint is — and so is sending the
// customer's data to somebody else, which is a consequence for them rather than for the target.
const (
	// EffectNetwork sends traffic to the target rather than reading an artifact. Probing a host
	// you do not own is unlawful in many jurisdictions, which is why it is worth stating even
	// though it changes nothing.
	EffectNetwork EffectKind = "network"
	// EffectDisclosure sends information about the target to a third party. The target is
	// unaffected; somebody else learns something about it.
	//
	// Distinct from EffectNetwork because the risk is a different one and lands on a different
	// party. Network traffic asks whether you are entitled to probe a host. This asks whether you
	// are content for a vendor to know what you just told them — a hostname, a dependency
	// manifest, a repository's source. Reported as the same kind, a reputation lookup and a
	// source-code upload would be indistinguishable in a report, and they are not remotely the
	// same decision.
	//
	// Detail carries what is actually sent, which is where the whole range lives.
	EffectDisclosure EffectKind = "disclosure"
	// EffectMutate creates or changes something that outlives the scan.
	EffectMutate EffectKind = "mutate"
	// EffectPrivilege needs access beyond what reading the target requires.
	EffectPrivilege EffectKind = "privilege"
)

// RequiresConsent reports whether an effect must be acknowledged before a scanner runs.
//
// Mutating a target or asking for elevated access is a decision someone should make on purpose.
//
// Network traffic and disclosure are declared and recorded but not gated: the controls that do
// them exist to do them, and demanding consent per run for the thing the control is *for* trains
// people to agree without reading. Both carry an obligation that is stated rather than enforced —
// that you are entitled to probe the host, and that you are content for the third party to know
// what you sent. A scanner that discloses also needs a credential the operator had to go and
// obtain, so the decision was already made somewhere it could be thought about.
//
// An organisation wanting to forbid disclosure outright wants a policy, not a per-run prompt.
// That belongs in configuration rather than here, where it would become a keystroke everybody
// learns to skip.
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

// EffectKinds is every effect a scanner can declare, most consequential first.
//
// Exported so the Saga schema's `allowEffects` enum is generated from the taxonomy rather than
// restated beside it. The two were maintained separately, which meant adding a kind left the
// schema rejecting a value Draugr accepts — an editor disagreeing with the binary, which is the
// same drift the generated control names exist to prevent.
func EffectKinds() []EffectKind {
	return []EffectKind{EffectMutate, EffectPrivilege, EffectNetwork, EffectDisclosure}
}

// Describe explains a kind in one line, for a schema tooltip or a listing.
func (k EffectKind) Describe() string {
	switch k {
	case EffectMutate:
		return "creates or changes something that outlives the scan"
	case EffectPrivilege:
		return "needs access beyond what reading the target requires"
	case EffectNetwork:
		return "sends traffic to the target rather than reading an artifact"
	case EffectDisclosure:
		return "sends information about the target to a third party"
	default:
		return string(k)
	}
}
