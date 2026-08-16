package report

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// TestActionableFindingsComeFirstWithinTheirBand is the answer to "should these fields change
// priority" — they should not, and this is what they do instead.
//
// Priority feeds the gate, so demoting a finding because nobody here can fix it would weaken a
// build gate as a side effect of annotating a descriptor. The risk is unchanged too: a vulnerable
// control plane is exactly as dangerous whether or not the fix is yours. Ordering is the honest
// half — two findings that matter equally, and one of them has somewhere to start.
func TestActionableFindingsComeFirstWithinTheirBand(t *testing.T) {
	fs := []finding{
		{ruleID: "external", priority: "P1", remediation: sarif.RemediationExternal, score: 9.8},
		{ruleID: "none", priority: "P1", remediation: sarif.RemediationNone, score: 9.8},
		{ruleID: "upstream", priority: "P1", remediation: sarif.RemediationUpstream, score: 9.8},
		{ruleID: "upgrade", priority: "P1", remediation: sarif.RemediationUpgrade, score: 9.8},
		{ruleID: "p2-upgrade", priority: "P2", remediation: sarif.RemediationUpgrade, score: 9.9},
	}
	sortFindings(fs)

	var order []string
	for _, f := range fs {
		order = append(order, f.ruleID)
	}
	want := []string{"upgrade", "upstream", "none", "external", "p2-upgrade"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

// TestPriorityStillDecidesOrderingFirst: actionability breaks ties, it does not outrank a band.
// A P1 nobody can fix is still more urgent than a P4 anybody can.
func TestPriorityStillDecidesOrderingFirst(t *testing.T) {
	fs := []finding{
		{ruleID: "easy-p4", priority: "P4", remediation: sarif.RemediationUpgrade, score: 1},
		{ruleID: "hard-p1", priority: "P1", remediation: sarif.RemediationExternal, score: 9.8},
	}
	sortFindings(fs)
	if fs[0].ruleID != "hard-p1" {
		t.Errorf("an actionable P4 outranked a P1: %s first", fs[0].ruleID)
	}
}

// TestScoreStillBreaksTiesAmongEquallyActionableFindings keeps the existing ordering underneath.
func TestScoreStillBreaksTiesAmongEquallyActionableFindings(t *testing.T) {
	fs := []finding{
		{ruleID: "lower", priority: "P1", remediation: sarif.RemediationUpgrade, score: 7.1},
		{ruleID: "higher", priority: "P1", remediation: sarif.RemediationUpgrade, score: 9.8},
	}
	sortFindings(fs)
	if fs[0].ruleID != "higher" {
		t.Errorf("score no longer breaks the tie: %s first", fs[0].ruleID)
	}
}
