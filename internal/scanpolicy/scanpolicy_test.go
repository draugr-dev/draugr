package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestDefaultPrioritizerWithoutEnrichment(t *testing.T) {
	p := DefaultPrioritizer(nil)
	got := p("sca", saga.ExposurePublic, saga.CriticalityCritical,
		sarif.Result{RuleID: "CVE-2019-20477", Level: sarif.LevelError, Score: 9.8, HasScore: true})

	if got.Band == "" {
		t.Error("no band was computed")
	}
	// Nothing enriched it, so nothing is claimed. A nil source must not manufacture a reason.
	if got.Escalation != nil {
		t.Errorf("escalation without a source: %+v", got.Escalation)
	}
}

func TestDefaultPrioritizerRecordsWhy(t *testing.T) {
	src := exploit.New(map[string]bool{"CVE-2024-3094": true}, nil, 0.5)
	p := DefaultPrioritizer(src)

	// A medium finding CISA has observed being exploited: ranked as critical, and the band has
	// to come out higher than the same finding without the signal.
	res := sarif.Result{RuleID: "CVE-2024-3094", Level: sarif.LevelWarning, Score: 5.0, HasScore: true}
	with := p("sca", saga.ExposurePublic, saga.CriticalityCritical, res)
	without := DefaultPrioritizer(nil)("sca", saga.ExposurePublic, saga.CriticalityCritical, res)

	if with.Escalation == nil || with.Escalation.To != sarif.SeverityCritical {
		t.Fatalf("escalation = %+v", with.Escalation)
	}
	if with.Escalation.From != sarif.SeverityMedium {
		t.Errorf("From = %q, want the scanner's own rating", with.Escalation.From)
	}
	if with.Band == without.Band {
		t.Errorf("the signal changed nothing: both %q", with.Band)
	}
}

func TestDefaultPrioritizerAppliesTheControlFloor(t *testing.T) {
	// secrets has a severity floor: a scanner that under-rates a leaked key must not be able to
	// rank it low. Checked here because the floor is applied before enrichment, and swapping the
	// order would let a floor overwrite a signal.
	p := DefaultPrioritizer(nil)
	got := p("secrets", saga.ExposurePublic, saga.CriticalityCritical,
		sarif.Result{RuleID: "private-key", Level: sarif.LevelNote})
	if got.Band != "P1" {
		t.Errorf("band = %q, want P1 for a secret on a public, critical component", got.Band)
	}
}
