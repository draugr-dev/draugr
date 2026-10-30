package skald

import (
	"strings"
	"testing"
)

// TestATermReadsInTheServersPhrases: every surface words a setting's terms from one closed set, so
// the console and the server's pages say the same thing about one verdict.
func TestATermReadsInTheServersPhrases(t *testing.T) {
	for _, c := range []struct {
		v    PolicyVerdict
		want string
	}{
		{PolicyVerdict{Mode: "observe"}, "observed"},
		{PolicyVerdict{Mode: "enforce", Response: "fail", EnforceFrom: "2026-10-01", InForce: true}, "fails the gate, since 2026-10-01"},
		{PolicyVerdict{Mode: "enforce", Response: "fail", EnforceFrom: "2026-11-01"}, "fails the gate from 2026-11-01"},
		{PolicyVerdict{Mode: "enforce", Response: "refuse", EnforceFrom: "2026-10-01", InForce: true}, "refuses, since 2026-10-01"},
		{PolicyVerdict{Mode: "enforce", Response: "refuse", EnforceFrom: "2026-12-01"}, "refuses from 2026-12-01"},
		// Broken only in its findings, after the publish was answered: the server failed the run.
		{PolicyVerdict{Mode: "enforce", Response: "refuse", EnforceFrom: "2026-10-01", InForce: true, Acts: "fail"}, "fails the gate, since 2026-10-01"},
		{PolicyVerdict{Mode: "enforce", Response: "refuse", EnforceFrom: "2026-10-01", InForce: true, Acts: "refuse"}, "refuses, since 2026-10-01"},
		{PolicyVerdict{Mode: "enforce", Response: "strip", EnforceFrom: "2026-10-01", InForce: true}, "removes the addresses, since 2026-10-01"},
		{PolicyVerdict{Mode: "enforce", Response: "fail", Override: "profile-observing"}, "observed, profile observing"},
		{PolicyVerdict{Mode: "enforce", Response: "fail", ProfileState: "observing"}, "observed, profile observing"},
		{PolicyVerdict{Mode: "enforce", Response: "fail", Override: "paused"}, "observed, enforcement paused"},
		{PolicyVerdict{Mode: "enforce", Response: "fail"}, "fails the gate"},
	} {
		if got := c.v.Term(); got != c.want {
			t.Errorf("Term(%+v) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestAnItemJoinsItsFourParts(t *testing.T) {
	i := PolicyItem{Field: "failOn", Found: "P1", Constraint: "required", Expected: "P2 or stricter"}
	if got := i.String(); got != "failOn: P1 · required: P2 or stricter" {
		t.Errorf("String() = %q", got)
	}
}

func TestStrongestAndSummary(t *testing.T) {
	if Strongest("none", "fail") != "fail" || Strongest("refuse", "fail") != "refuse" || Strongest("", "none") != "" {
		t.Error("refuse outranks fail, which outranks none")
	}
	p := PolicyOutcome{Verdicts: []PolicyVerdict{
		{Rule: "threshold", Profile: "PCI scope", State: "violates", Mode: "enforce", Response: "fail", EnforceFrom: "2026-10-01",
			InForce: true, Acts: "fail", Items: []PolicyItem{
				{Field: "failOn", Found: "P1", Constraint: "required", Expected: "P2 or stricter", Breaks: true},
				{Field: "controls.licenses", Found: "P3", Constraint: "required", Expected: "P3 or stricter"},
			}},
		{Rule: "scanners", Profile: "Default", State: "violates", Mode: "observe", Acts: "none"},
	}}
	got := p.Summary("fail")
	if got != "threshold failOn: P1 · required: P2 or stricter (PCI scope · fails the gate, since 2026-10-01)" || strings.Contains(got, "scanners") {
		t.Errorf("Summary = %q", got)
	}
	if v := (PolicyVerdict{Items: []PolicyItem{{Field: "a"}, {Field: "b"}}}); len(v.Breaking()) != 2 {
		t.Error("with no item marked, every item is what the verdict names")
	}
}

func TestAnOutcomeIsUndecidedWhileAnythingIsPending(t *testing.T) {
	if (PolicyOutcome{Outcome: PolicyNone, Passed: true}).Undecided() {
		t.Error("an answer with nothing pending is decided")
	}
	if !(PolicyOutcome{Pending: true}).Undecided() {
		t.Error("the run's answer says pending")
	}
	if !(PolicyOutcome{Verdicts: []PolicyVerdict{{Rule: "licenses"}, {Rule: "threshold", Pending: true}}}).Undecided() {
		t.Error("a publish answer marks the pending verdict")
	}
}

func TestACheckFailsOnFailOrRefuse(t *testing.T) {
	for outcome, fails := range map[string]bool{PolicyNone: false, "": false, PolicyFail: true, PolicyRefuse: true} {
		if got := (&PolicyCheck{Outcome: outcome}).Fails(); got != fails {
			t.Errorf("%q fails = %v", outcome, got)
		}
	}
	var none *PolicyCheck
	if none.Fails() {
		t.Error("no check fails nothing")
	}
}
