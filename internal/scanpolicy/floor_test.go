package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The contradiction this closes: `secrets` escalates every finding's severity because a
// credential does not vary in seriousness the way a CVE does, and the priority model then applies
// exposure, which is premised on exactly that variation. A reader was told nothing is urgent and
// that they cannot ship, in the same six lines, from the same finding.
func TestSecretsAreNotDampedToRoutineByExposure(t *testing.T) {
	p := DefaultPrioritizer(nil)
	res := sarif.Result{RuleID: "github-pat", Level: sarif.LevelError}

	got := p("secrets", saga.ExposureInternal, saga.CriticalitySupporting, res)
	if got.Band != "P2" {
		t.Errorf("band = %q, want P2 — the least exposed component still holds a live credential", got.Band)
	}
	if got.Floor == "" {
		t.Error("a band the classification does not account for must say why")
	}
}

// A floor, not a fixed band. Where exposure and criticality already rank a credential higher,
// they still do.
func TestTheFloorOnlyRaises(t *testing.T) {
	p := DefaultPrioritizer(nil)
	res := sarif.Result{RuleID: "github-pat", Level: sarif.LevelError}

	got := p("secrets", saga.ExposurePublic, saga.CriticalityCritical, res)
	if got.Band != "P1" {
		t.Errorf("band = %q, want P1 on a public critical component", got.Band)
	}
	if got.Floor != "" {
		t.Error("the matrices' own answer stood, so nothing should claim a floor applied")
	}
}

// Everything else is unchanged: for a dependency CVE, where the component sits is exactly what
// decides how much it matters, and that is the model working correctly.
func TestControlsWithoutAFloorAreUnaffected(t *testing.T) {
	p := DefaultPrioritizer(nil)
	res := sarif.Result{RuleID: "CVE-2026-0001", Level: sarif.LevelError, Score: 8.1, HasScore: true}

	got := p("sca", saga.ExposureInternal, saga.CriticalitySupporting, res)
	if got.Band != "P3" {
		t.Errorf("band = %q, want P3 — exposure should still damp an sca finding", got.Band)
	}
	if got.Floor != "" {
		t.Errorf("sca declares no floor, got %q", got.Floor)
	}
}
