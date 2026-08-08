// Package scanpolicy holds the scoring choices a scan makes, so every entry point into Draugr
// makes the same ones. The CLI and the MCP server both run scans; if they prioritized
// differently, the answer an agent gave and the answer CI gave would diverge for no reason a
// user could see.
package scanpolicy

import (
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
		}
	}
}
