// Package scanpolicy holds the scoring choices a scan makes, so every entry point into Draugr
// makes the same ones. The CLI and the MCP server both run scans; if they prioritized
// differently, the answer an agent gave and the answer CI gave would diverge for no reason a
// user could see.
package scanpolicy

import (
	"slices"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// DefaultPrioritizer scores a finding from its severity and the component's declared exposure
// and criticality, optionally escalating on exploitability. expl may be nil, in which case
// enrichment is skipped.
func DefaultPrioritizer(expl *exploit.Source) engine.Prioritizer {
	matrices := prioritization.DefaultMatrices()
	return func(control string, exposure saga.Exposure, criticality saga.Criticality, res sarif.Result) engine.Priority {
		sev := res.Severity(controllers.SeverityFloor(control))
		// nil-safe: no-op when no source, and the escalation is nil unless something moved.
		sev, esc := expl.Explain(sev, res.RuleID)
		// Reachability ranks a finding down when nothing can reach it, but never one that
		// exploitability just raised.
		//
		// The asymmetry is confidence in a negative rather than observation against prediction.
		// An unreachable verdict is an absence claim: it says analysis found no route today, on one
		// revision, and reflection, dynamic dispatch and code generation all defeat a call graph.
		// The route appears the day somebody writes the call. A wrong absence claim costs most
		// exactly where the flaw is one people are already exploiting, so "we could not find a
		// path" does not overturn "this is being used".
		//
		// Not the reason KEV outranks EPSS, which is a different comparison. Those two answer the
		// same question, is this being exploited, and the one that observed it beats the one that
		// predicted it. This pair answers two questions about two subjects: exploitation is about
		// the world, reachability is about this codebase, and neither is automatically the stronger
		// claim. What decides it is which claim is easier to be wrong about.
		var rankedAs sarif.Severity
		if esc == nil {
			if lowered := res.Reachability.RankAt(sev); lowered != sev {
				sev, rankedAs = lowered, lowered
			}
		}
		// The context tier first, so a control that declares exposure does not bound its findings
		// replaces the component's tier rather than second-guessing the band that came out of it.
		// Severity still decides the row: a critical secret and a high one must not collapse into
		// one band because they share a control.
		tier := matrices.ContextOf(exposure, criticality)
		var floorReason string
		if floor, reason := controllers.ContextFloor(control); floor.Rank() > tier.Rank() {
			tier, floorReason = floor, reason
		}
		band := matrices.PriorityOf(tier, sev)
		return engine.Priority{
			Band:       string(band),
			Escalation: esc,
			Floor:      floorReason,
			RankedAs:   rankedAs,
		}
	}
}

// GateThresholds converts a descriptor's gate block into the per-control map a Policy takes.
// Nil when unset, which leaves every control on the default threshold.
//
// Here rather than beside either caller for the reason in the package doc. A verdict is the
// answer Draugr exists to give, and one entry point applying the descriptor's gate while another
// applied a fixed default would have an agent and CI disagree about the same descriptor. With
// nothing in either answer to show which policy produced it.
//
// Validation has already refused a per-control threshold in the other vocabulary from the gate, so
// the two maps are never both populated and a value that parses as neither cannot reach here.
//
// Returned as two maps because a threshold only means something in the vocabulary its gate asks
// in. Parsing every value as a severity and keeping what survived silently discarded a band, which
// is the whole per-control block on a band gate, and a band gate is the default.
func GateThresholds(g *saga.GateConfig) (map[string]sarif.Severity, map[string]string) {
	if g == nil || len(g.Controls) == 0 {
		return nil, nil
	}
	severities := map[string]sarif.Severity{}
	bands := map[string]string{}
	for control, want := range g.Controls {
		if slices.Contains(saga.Priorities, want) {
			bands[control] = want
			continue
		}
		if sev, err := sarif.ParseSeverity(want); err == nil {
			severities[control] = sev
		}
	}
	if len(severities) == 0 {
		severities = nil
	}
	if len(bands) == 0 {
		bands = nil
	}
	return severities, bands
}
