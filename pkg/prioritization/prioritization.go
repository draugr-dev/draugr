// Package prioritization turns a finding's severity and its component's risk classification
// (exposure × business criticality) into a single Priority band. It is the engine behind
// "what do I fix first": two small, auditable lookup matrices —
//
//	re × bc      → context tier (C1–C4)   "how much we care about any issue here"
//	context × severity → priority (P1–P4) "this finding's rank"
//
// The default matrices ship opinionated and are overridable. See
// docs/concepts.md (prioritization).
package prioritization

import (
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Context is the "how much we care about this component" tier (C1 highest concern, C4
// lowest), derived from exposure × criticality.
type Context string

// Context tiers, from most to least concerning.
const (
	C1 Context = "C1"
	C2 Context = "C2"
	C3 Context = "C3"
	C4 Context = "C4"
)

// Priority is a finding's action band (P1 most urgent, P4 least).
type Priority string

// Priority bands: P1 act now/block · P2 this cycle · P3 backlog · P4 track/accept.
const (
	P1 Priority = "P1"
	P2 Priority = "P2"
	P3 Priority = "P3"
	P4 Priority = "P4"
)

// Rank orders priorities by urgency (higher is more urgent): P1=4 … P4=1, unknown=0. Sort
// findings by descending Rank to put the most urgent first.
func (p Priority) Rank() int {
	switch p {
	case P1:
		return 4
	case P2:
		return 3
	case P3:
		return 2
	case P4:
		return 1
	default:
		return 0
	}
}

// Matrices holds the two lookup tables. The maps are exported so callers can start from
// DefaultMatrices and override individual cells (e.g. from Saga config).
type Matrices struct {
	// ContextTier maps exposure → criticality → context tier.
	ContextTier map[saga.Exposure]map[saga.Criticality]Context
	// PriorityBand maps context tier → normalized severity → priority.
	PriorityBand map[Context]map[sarif.Severity]Priority
}

// DefaultMatrices returns the shipped, opinionated matrices (a fresh copy, safe to mutate
// for overrides). Both are monotonic: raising exposure, criticality, or severity never
// lowers priority, and P1 is deliberately scarce. See docs/concepts.md (prioritization).
func DefaultMatrices() Matrices {
	return Matrices{
		ContextTier: map[saga.Exposure]map[saga.Criticality]Context{
			saga.ExposurePublic:        {saga.CriticalityCritical: C1, saga.CriticalityImportant: C1, saga.CriticalitySupporting: C2},
			saga.ExposureAuthenticated: {saga.CriticalityCritical: C1, saga.CriticalityImportant: C2, saga.CriticalitySupporting: C3},
			saga.ExposureInternal:      {saga.CriticalityCritical: C2, saga.CriticalityImportant: C3, saga.CriticalitySupporting: C4},
			saga.ExposureRestricted:    {saga.CriticalityCritical: C3, saga.CriticalityImportant: C4, saga.CriticalitySupporting: C4},
		},
		PriorityBand: map[Context]map[sarif.Severity]Priority{
			C1: {sarif.SeverityCritical: P1, sarif.SeverityHigh: P1, sarif.SeverityMedium: P2, sarif.SeverityLow: P3},
			C2: {sarif.SeverityCritical: P1, sarif.SeverityHigh: P2, sarif.SeverityMedium: P2, sarif.SeverityLow: P3},
			C3: {sarif.SeverityCritical: P2, sarif.SeverityHigh: P3, sarif.SeverityMedium: P3, sarif.SeverityLow: P4},
			C4: {sarif.SeverityCritical: P2, sarif.SeverityHigh: P3, sarif.SeverityMedium: P4, sarif.SeverityLow: P4},
		},
	}
}

// ContextOf returns the context tier for a component's classification. Unclassified or
// unknown exposure/criticality is treated as the most severe level (public / critical), so findings
// on unclassified components surface rather than hide.
func (m Matrices) ContextOf(exposure saga.Exposure, criticality saga.Criticality) Context {
	if !exposure.Valid() {
		exposure = saga.ExposurePublic
	}
	if !criticality.Valid() {
		criticality = saga.CriticalityCritical
	}
	if byCrit, ok := m.ContextTier[exposure]; ok {
		if ctx, ok := byCrit[criticality]; ok {
			return ctx
		}
	}
	return C1 // defensive: an incomplete override falls back to highest concern
}

// PriorityOf returns the priority band for a context tier and a normalized severity. An
// unknown severity is treated as low.
func (m Matrices) PriorityOf(ctx Context, severity sarif.Severity) Priority {
	if severity.Rank() == 0 {
		severity = sarif.SeverityLow
	}
	if bySev, ok := m.PriorityBand[ctx]; ok {
		if p, ok := bySev[severity]; ok {
			return p
		}
	}
	return P2 // defensive: an incomplete override falls back to a mid band
}

// Prioritize combines both matrices: it ranks a finding of the given severity on a component
// with the given exposure and criticality.
func (m Matrices) Prioritize(exposure saga.Exposure, criticality saga.Criticality, severity sarif.Severity) Priority {
	return m.PriorityOf(m.ContextOf(exposure, criticality), severity)
}
