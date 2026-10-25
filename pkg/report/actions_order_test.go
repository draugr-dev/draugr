package report

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// ratedDep is a dependency finding with a severity, and with the exploitation signal that raised it
// when signal is not empty.
func ratedDep(rule, name string, sev sarif.Severity, signal string) finding {
	f := pkgFinding("sca", rule, "P1", "go.mod", name, "1.0", "1.1")
	f.severity = sev
	if signal != "" {
		f.escalation = &sarif.Escalation{From: sev, To: sev.Escalate(), Signal: signal}
	}
	return f
}

// packages is the order the actions name their packages in.
func packages(as []action) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.findings[0].pkg.Name)
	}
	return out
}

// TestActionsRankInsideABandByEvidenceThenSeverityThenCount holds each key of the order to deciding
// only between actions alike in every key above it. Count comes last because a scanner reporting
// one finding per package per advisory decides it, so an upgrade clearing many findings nobody is
// known to exploit must not outrank one fix for a flaw on KEV.
func TestActionsRankInsideABandByEvidenceThenSeverityThenCount(t *testing.T) {
	in := []finding{
		// Many critical findings, no exploitation evidence.
		ratedDep("CVE-1", "plentiful", sarif.SeverityCritical, ""),
		ratedDep("CVE-2", "plentiful", sarif.SeverityCritical, ""),
		ratedDep("CVE-3", "plentiful", sarif.SeverityCritical, ""),
		// One high finding EPSS raised.
		ratedDep("CVE-4", "estimated", sarif.SeverityHigh, "epss"),
		// One medium finding on KEV.
		ratedDep("CVE-5", "exploited", sarif.SeverityMedium, "kev"),
		// One critical finding, no evidence: above "plentiful" on nothing, below it on count.
		ratedDep("CVE-6", "single", sarif.SeverityCritical, ""),
		// Two high findings, no evidence: below every critical.
		ratedDep("CVE-7", "lesser", sarif.SeverityHigh, ""),
		ratedDep("CVE-8", "lesser", sarif.SeverityHigh, ""),
	}
	got, _ := groupActions(in, nil)
	want := []string{"exploited", "estimated", "plentiful", "single", "lesser"}
	if order := packages(got); !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
}

// TestActionsRankBySeverityTheBandCameFrom: an unreachable finding whose band was computed from a
// lowered severity ranks as that severity, so the order inside a band continues the reasoning
// that set the band rather than going back to what the scanner said.
func TestActionsRankBySeverityTheBandCameFrom(t *testing.T) {
	lowered := ratedDep("CVE-1", "lowered", sarif.SeverityCritical, "")
	lowered.reachability = &sarif.Reachability{State: sarif.ReachabilityUnreachable, RankedAs: sarif.SeverityMedium}
	in := []finding{lowered, ratedDep("CVE-2", "high", sarif.SeverityHigh, "")}
	got, _ := groupActions(in, nil)
	if order := packages(got); !reflect.DeepEqual(order, []string{"high", "lowered"}) {
		t.Errorf("order = %v, want the high finding ahead of the one lowered to medium", order)
	}
}

// TestPriorityStillLeadsTheEvidence: a KEV finding in a lower band does not outrank a higher band.
// The band already folds the evidence in, and the keys below it decide only inside one.
func TestPriorityStillLeadsTheEvidence(t *testing.T) {
	kev := ratedDep("CVE-1", "exploited", sarif.SeverityMedium, "kev")
	kev.priority = "P2"
	in := []finding{kev, ratedDep("CVE-2", "urgent", sarif.SeverityLow, "")}
	got, _ := groupActions(in, nil)
	if order := packages(got); !reflect.DeepEqual(order, []string{"urgent", "exploited"}) {
		t.Errorf("order = %v, want the P1 ahead of the P2 on KEV", order)
	}
}

// TestBothStepsOfAnUpgradeRankByWhatEitherClears: the evidence on the step beyond the policy ranks
// the package, and the step within the policy is still listed first, because the other presumes it.
func TestBothStepsOfAnUpgradeRankByWhatEitherClears(t *testing.T) {
	within := upgradeFinding("CVE-1", "P1", "web", "minor", "npm", "jquery", "1.8.3", "1.9.0")
	within.severity = sarif.SeverityHigh
	beyond := upgradeFinding("CVE-2", "P1", "web", "minor", "npm", "jquery", "1.8.3", "3.5.0")
	beyond.severity = sarif.SeverityHigh
	beyond.escalation = &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical, Signal: "kev"}
	in := []finding{
		ratedDep("CVE-3", "plentiful", sarif.SeverityCritical, ""),
		ratedDep("CVE-4", "plentiful", sarif.SeverityCritical, ""),
		ratedDep("CVE-5", "plentiful", sarif.SeverityCritical, ""),
		within, beyond,
	}
	got, _ := groupActions(in, nil)
	if len(got) != 3 {
		t.Fatalf("got %d actions, want the two jquery steps and plentiful", len(got))
	}
	if order := packages(got); !reflect.DeepEqual(order, []string{"jquery", "jquery", "plentiful"}) {
		t.Errorf("order = %v, want both jquery steps first, on the KEV finding the second clears", order)
	}
	if got[0].key == got[1].key || got[1].key != got[0].key+"\x00beyond" {
		t.Errorf("the step within the policy should come first: %q then %q", got[0].key, got[1].key)
	}
}
