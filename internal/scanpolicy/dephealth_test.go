package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func pkgResult(rule, purl string, level sarif.Level) sarif.Result {
	return sarif.Result{
		RuleID: rule, Level: level,
		Package: &sarif.Package{Name: "x", Version: "1", PURL: purl},
	}
}

// The signal reaches the band at all, which is the whole wiring in one assertion.
func TestADeprecatedPackageRanksHigher(t *testing.T) {
	health := dephealth.New(map[string]dephealth.Package{
		"pkg:npm/jquery@1.8.3": {Findings: []dephealth.Finding{
			{Kind: dephealth.KindDeprecated, Reason: "no longer supported"},
		}},
	}, "2026-09-20")

	plain := PrioritizerWith(nil, nil)
	enriched := PrioritizerWith(nil, health)
	res := pkgResult("CVE-1", "pkg:npm/jquery@1.8.3", sarif.LevelWarning)

	before := plain("sca", saga.ExposureInternal, saga.CriticalitySupporting, res)
	after := enriched("sca", saga.ExposureInternal, saga.CriticalitySupporting, res)

	if before.Escalation != nil {
		t.Fatalf("nothing was configured and something was claimed: %+v", before.Escalation)
	}
	if after.Escalation == nil || after.Escalation.Signal != dephealth.SignalDeprecated {
		t.Fatalf("the deprecation did not reach the ranking: %+v", after.Escalation)
	}
	if after.Band == before.Band {
		t.Errorf("the band did not move: %s both times", after.Band)
	}
}

// A finding about no package is most of sast, iac and secrets. It carries no purl and must pass
// through untouched rather than matching an empty key.
func TestAFindingAboutNoPackageIsUntouched(t *testing.T) {
	health := dephealth.New(map[string]dephealth.Package{
		"": {Findings: []dephealth.Finding{{Kind: dephealth.KindMalicious}}},
	}, "2026-09-20")
	p := PrioritizerWith(nil, health)

	got := p("secrets", saga.ExposurePublic, saga.CriticalityCritical,
		sarif.Result{RuleID: "private-key", Level: sarif.LevelError})
	if got.Escalation != nil {
		t.Errorf("a finding with no package was enriched: %+v", got.Escalation)
	}
}

// Both enrichments can fire on one finding, and they answer different questions. The higher
// resulting severity wins, so a malicious package is not held down by an EPSS bump that reached a
// lower band first.
func TestTheStrongerOfTheTwoEnrichmentsWins(t *testing.T) {
	// EPSS alone would raise medium to high.
	expl := exploit.New(nil, map[string]float64{"CVE-2020-1111": 0.9}, 0.5)
	health := dephealth.New(map[string]dephealth.Package{
		"pkg:npm/evil@1.0.0": {Findings: []dephealth.Finding{{Kind: dephealth.KindMalicious}}},
	}, "2026-09-20")

	p := PrioritizerWith(expl, health)
	got := p("sca", saga.ExposureInternal, saga.CriticalitySupporting,
		pkgResult("CVE-2020-1111", "pkg:npm/evil@1.0.0", sarif.LevelWarning))

	if got.Escalation == nil {
		t.Fatal("neither enrichment was recorded")
	}
	if got.Escalation.Signal != dephealth.SignalMalicious {
		t.Errorf("EPSS held down a malicious package: %+v", got.Escalation)
	}
	if got.Escalation.To != sarif.SeverityCritical {
		t.Errorf("ranked as %s, wanted critical", got.Escalation.To)
	}
}

// Where both reach the same band, the statement about this specific flaw is the more useful thing
// to show. A tie goes to exploitability.
func TestExploitabilityTakesATie(t *testing.T) {
	expl := exploit.New(map[string]bool{"CVE-2020-2222": true}, nil, 0.5) // KEV → critical
	health := dephealth.New(map[string]dephealth.Package{
		"pkg:npm/evil@1.0.0": {Findings: []dephealth.Finding{{Kind: dephealth.KindMalicious}}},
	}, "2026-09-20")

	p := PrioritizerWith(expl, health)
	got := p("sca", saga.ExposureInternal, saga.CriticalitySupporting,
		pkgResult("CVE-2020-2222", "pkg:npm/evil@1.0.0", sarif.LevelWarning))

	if got.Escalation == nil || got.Escalation.Signal != exploit.SignalKEV {
		t.Errorf("a tie did not go to the signal about this flaw: %+v", got.Escalation)
	}
}

// The signal switched off is the default, and it must claim nothing.
func TestNoHealthSourceClaimsNothing(t *testing.T) {
	p := PrioritizerWith(nil, nil)
	got := p("sca", saga.ExposurePublic, saga.CriticalityCritical,
		pkgResult("CVE-3", "pkg:npm/jquery@1.8.3", sarif.LevelError))
	if got.Escalation != nil {
		t.Errorf("an unconfigured signal explained something: %+v", got.Escalation)
	}
}
