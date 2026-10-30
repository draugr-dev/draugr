package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The contradiction this closes: `secrets` escalates every finding's severity because a
// credential does not vary in seriousness the way a CVE does, and the priority model then applies
// exposure, which is premised on exactly that variation. A reader was told nothing is urgent and
// that they cannot ship, in the same six lines, from the same finding.
//
// P1 rather than something short of it, for two reasons. `--fail-on-priority P1` is the gate this
// project documents and dogfoods, so anything below it means a credential fails the severity gate
// and passes the priority one, the same contradiction, one band over. And the claim being made is
// that exposure does not bound the finding; a band that still moves with exposure, only less, is
// a third position nothing argues for.
func TestSecretsAreRankedAsIfTheComponentWereTheMostExposed(t *testing.T) {
	p := DefaultPrioritizer(nil)
	res := sarif.Result{RuleID: "github-pat", Level: sarif.LevelError}

	// The least exposed, least critical classification a descriptor can express.
	got := p("secrets", saga.ExposureRestricted, saga.CriticalitySupporting, res)
	if got.Band != "P1" {
		t.Errorf("band = %q, want P1, a credential is valid wherever it is valid", got.Band)
	}
	if got.Floor == "" {
		t.Error("a band the classification does not account for must say why")
	}
}

// A context tier, not a fixed band: severity is still the scanner's and the severity floor's to
// answer, so two secrets findings of different severities must not collapse into one row.
//
// The severity floor puts every secrets finding at `high` or above, so both land on P1 today at
// C1. What this pins is that the band comes from the severity, so a future change to either
// matrix keeps working rather than being overridden by a hardcoded band.
func TestSecretsStillRankBySeverity(t *testing.T) {
	p := DefaultPrioritizer(nil)
	matrices := prioritization.DefaultMatrices()

	for _, sev := range []sarif.Severity{sarif.SeverityCritical, sarif.SeverityHigh} {
		res := sarif.Result{RuleID: "x", Score: scoreFor(sev), HasScore: true, Level: sarif.LevelError}
		want := string(matrices.PriorityOf(prioritization.C1, sev))
		if got := p("secrets", saga.ExposureInternal, saga.CriticalitySupporting, res); got.Band != want {
			t.Errorf("%s: band = %q, want %q, the band must come from the severity at C1",
				sev, got.Band, want)
		}
	}
}

// Where the component's own classification is already the most concerning, nothing was overridden
// and nothing should claim it was.
func TestNothingIsClaimedWhenTheClassificationAlreadyAgrees(t *testing.T) {
	p := DefaultPrioritizer(nil)
	res := sarif.Result{RuleID: "github-pat", Level: sarif.LevelError}

	got := p("secrets", saga.ExposurePublic, saga.CriticalityCritical, res)
	if got.Band != "P1" {
		t.Errorf("band = %q, want P1 on a public critical component", got.Band)
	}
	if got.Floor != "" {
		t.Error("the component's own tier stood, so nothing should claim it was replaced")
	}
}

// Everything else is unchanged: for a dependency CVE, where the component sits is exactly what
// decides how much it matters, and that is the model working correctly.
func TestControlsWithoutAFloorAreUnaffected(t *testing.T) {
	p := DefaultPrioritizer(nil)
	res := sarif.Result{RuleID: "CVE-2026-0001", Level: sarif.LevelError, Score: 8.1, HasScore: true}

	got := p("sca", saga.ExposureInternal, saga.CriticalitySupporting, res)
	if got.Band != "P3" {
		t.Errorf("band = %q, want P3, exposure should still damp an sca finding", got.Band)
	}
	if got.Floor != "" {
		t.Errorf("sca declares no floor, got %q", got.Floor)
	}
}

// scoreFor is the CVSS-style score that normalizes to a severity, so a test can ask for one.
func scoreFor(s sarif.Severity) float64 {
	switch s {
	case sarif.SeverityCritical:
		return 9.5
	case sarif.SeverityHigh:
		return 8.0
	case sarif.SeverityMedium:
		return 5.0
	default:
		return 2.0
	}
}

// Every report's Signals section says the floor moves a finding's "priority to P1". That holds
// because the floor ranks a finding at the tier of a public, critical component, and the controls
// that declare one also hold their findings at high or above, so a floored finding is that tier
// crossed with high or critical. A floor on a control whose findings can be medium lands them on
// P2 and leaves the row untrue, so this fails rather than letting it.
//
// Every control with a floor, every classification a descriptor can declare, and every severity a
// finding can arrive with: by level, by score and by a scanner's rating.
func TestEveryFlooredFindingIsP1(t *testing.T) {
	p := DefaultPrioritizer(nil)
	exposures := append([]saga.Exposure{""}, saga.Exposures...)
	criticalities := append([]saga.Criticality{""}, saga.Criticalities...)

	var findings []sarif.Result
	for _, level := range []sarif.Level{sarif.LevelError, sarif.LevelWarning, sarif.LevelNote, sarif.LevelNone} {
		findings = append(findings, sarif.Result{RuleID: "generic-api-key", Level: level})
		for _, sev := range []sarif.Severity{sarif.SeverityCritical, sarif.SeverityHigh, sarif.SeverityMedium, sarif.SeverityLow} {
			findings = append(findings,
				sarif.Result{RuleID: "generic-api-key", Level: level, Score: scoreFor(sev), HasScore: true},
				sarif.Result{RuleID: "generic-api-key", Level: level, Rating: &sarif.Rating{Severity: sev}})
		}
	}

	floored := 0
	for _, control := range controllers.ControlsWithContextFloor() {
		for _, exposure := range exposures {
			for _, criticality := range criticalities {
				for _, res := range findings {
					got := p(control, exposure, criticality, res)
					if got.Floor == "" {
						continue
					}
					floored++
					if got.Band != "P1" {
						t.Errorf("%s on %q/%q, %s finding: band %s with a floor, want P1; the Signals "+
							"section says the floor moves a finding to P1",
							control, exposure, criticality, res.Severity(""), got.Band)
					}
				}
			}
		}
	}
	if floored == 0 {
		t.Fatal("no finding was floored, so nothing here was checked")
	}
}
