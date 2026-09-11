package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/norn"
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

func TestGateThresholds(t *testing.T) {
	if sev, band := GateThresholds(nil); sev != nil || band != nil {
		t.Errorf("no gate block should leave every control on the default, got %v %v", sev, band)
	}
	if sev, band := GateThresholds(&saga.GateConfig{}); sev != nil || band != nil {
		t.Errorf("an empty gate block is the same as none, got %v %v", sev, band)
	}
	got, bands := GateThresholds(&saga.GateConfig{Controls: map[string]string{"licenses": "critical", "sast": "low"}})
	if len(got) != 2 || got["licenses"] != sarif.SeverityCritical || got["sast"] != sarif.SeverityLow {
		t.Errorf("GateThresholds = %v", got)
	}
	if bands != nil {
		t.Errorf("a severity gate has no per-control bands, got %v", bands)
	}
	// A descriptor written against the older vocabulary lands on the band each level means,
	// rather than being carried through as a word the gate no longer compares.
	legacy, _ := GateThresholds(&saga.GateConfig{Controls: map[string]string{"licenses": "error", "sast": "note"}})
	if legacy["licenses"] != sarif.SeverityHigh || legacy["sast"] != sarif.SeverityLow {
		t.Errorf("the levels a gate used to take should map onto bands, got %v", legacy)
	}
}

// A band per control is the shape the default gate takes, and it was parsed as a severity, failing,
// and dropped. The whole per-control block did nothing on every descriptor that used the gate the
// product recommends.
func TestAPerControlBandSurvives(t *testing.T) {
	sev, bands := GateThresholds(&saga.GateConfig{
		FailOn:   "P1",
		Controls: map[string]string{"licenses": "P2", "sca": "P3"},
	})
	if sev != nil {
		t.Errorf("a band gate has no per-control severities, got %v", sev)
	}
	if len(bands) != 2 || bands["licenses"] != "P2" || bands["sca"] != "P3" {
		t.Errorf("per-control bands = %v, want licenses P2 and sca P3", bands)
	}
}

// The descriptor's package and the policy engine each name the default gate, because neither can
// import the other without inverting the layering. Two constants for one value is a thing that
// drifts, and the drift is silent: a descriptor validated against one default and judged against
// another disagrees with itself about which findings fail.
func TestTheDefaultGateIsOneValue(t *testing.T) {
	if saga.DefaultGateBand != norn.DefaultPriority {
		t.Errorf("saga.DefaultGateBand = %q and norn.DefaultPriority = %q. A descriptor is "+
			"validated against the first and judged against the second, so they are one value",
			saga.DefaultGateBand, norn.DefaultPriority)
	}
}
