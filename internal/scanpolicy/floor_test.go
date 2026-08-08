package scanpolicy

import (
	"testing"

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
// and passes the priority one — the same contradiction, one band over. And the claim being made
// is that exposure does not bound the finding; a band that still moves with exposure, only less,
// is a third position nothing argues for.
func TestSecretsAreRankedAsIfTheComponentWereTheMostExposed(t *testing.T) {
	p := DefaultPrioritizer(nil)
	res := sarif.Result{RuleID: "github-pat", Level: sarif.LevelError}

	// The least exposed, least critical classification a descriptor can express.
	got := p("secrets", saga.ExposureRestricted, saga.CriticalitySupporting, res)
	if got.Band != "P1" {
		t.Errorf("band = %q, want P1 — a credential is valid wherever it is valid", got.Band)
	}
	if got.Floor == "" {
		t.Error("a band the classification does not account for must say why")
	}
}

// A context tier, not a fixed band: severity is still the scanner's and the severity floor's to
// answer, so two secrets findings of different severities must not collapse into one row.
//
// The severity floor puts every secrets finding at `high` or above, so both land on P1 today at
// C1 — what this pins is that the band comes from the severity, so a future change to either
// matrix keeps working rather than being overridden by a hardcoded band.
func TestSecretsStillRankBySeverity(t *testing.T) {
	p := DefaultPrioritizer(nil)
	matrices := prioritization.DefaultMatrices()

	for _, sev := range []sarif.Severity{sarif.SeverityCritical, sarif.SeverityHigh} {
		res := sarif.Result{RuleID: "x", Score: scoreFor(sev), HasScore: true, Level: sarif.LevelError}
		want := string(matrices.PriorityOf(prioritization.C1, sev))
		if got := p("secrets", saga.ExposureInternal, saga.CriticalitySupporting, res); got.Band != want {
			t.Errorf("%s: band = %q, want %q — the band must come from the severity at C1",
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
		t.Errorf("band = %q, want P3 — exposure should still damp an sca finding", got.Band)
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
