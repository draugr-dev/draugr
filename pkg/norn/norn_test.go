package norn

import (
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

func report(levels ...sarif.Level) sarif.Report {
	var r sarif.Report
	for _, l := range levels {
		r.Results = append(r.Results, sarif.Result{Level: l})
	}
	return r
}

func TestEvaluateDefaultFailsOnError(t *testing.T) {
	p := Policy{} // zero value => fail on error
	res := p.Evaluate(map[string]sarif.Report{
		"images": report(sarif.LevelError, sarif.LevelWarning),
	})
	if res.Verdict != Fail {
		t.Fatalf("verdict = %s, want fail", res.Verdict)
	}
	if res.Controls[0].Highest != sarif.SeverityHigh {
		t.Errorf("highest = %s", res.Controls[0].Highest)
	}
}

func TestEvaluatePassesBelowThreshold(t *testing.T) {
	p := Policy{} // fail on error
	res := p.Evaluate(map[string]sarif.Report{
		"sast": report(sarif.LevelWarning, sarif.LevelNote),
	})
	if res.Verdict != Pass {
		t.Fatalf("verdict = %s, want pass", res.Verdict)
	}
}

func TestEmptyReportPasses(t *testing.T) {
	p := Policy{FailOn: sarif.SeverityLow} // strict threshold
	res := p.Evaluate(map[string]sarif.Report{"images": {}})
	if res.Verdict != Pass {
		t.Fatalf("empty report should pass, got %s", res.Verdict)
	}
}

func TestPerControlOverride(t *testing.T) {
	p := Policy{
		FailOn:     sarif.SeverityHigh,
		PerControl: map[string]sarif.Severity{"headers": sarif.SeverityMedium},
	}
	res := p.Evaluate(map[string]sarif.Report{
		"headers": report(sarif.LevelWarning), // fails under stricter per-control threshold
	})
	if res.Verdict != Fail {
		t.Fatalf("verdict = %s, want fail (per-control threshold)", res.Verdict)
	}
	if res.Controls[0].Threshold != sarif.SeverityMedium {
		t.Errorf("threshold = %s, want warning", res.Controls[0].Threshold)
	}
}

func TestOverallFailsIfAnyControlFails(t *testing.T) {
	p := Policy{}
	res := p.Evaluate(map[string]sarif.Report{
		"a": report(sarif.LevelNote),
		"b": report(sarif.LevelError),
	})
	if res.Verdict != Fail {
		t.Fatalf("overall should fail if any control fails")
	}
	if len(res.Controls) != 2 {
		t.Errorf("want 2 control outcomes, got %d", len(res.Controls))
	}
}

func TestThresholdForFallbacks(t *testing.T) {
	// Empty per-control value falls back to FailOn.
	p := Policy{FailOn: sarif.SeverityMedium, PerControl: map[string]sarif.Severity{"x": ""}}
	if got := p.thresholdFor("x"); got != sarif.SeverityMedium {
		t.Errorf("thresholdFor empty override = %s, want warning", got)
	}
	if got := p.thresholdFor("unknown"); got != sarif.SeverityMedium {
		t.Errorf("thresholdFor unknown = %s, want warning", got)
	}
}

// reportWithPriority builds a report whose single finding has the given level and priority.
func reportWithPriority(level sarif.Level, priority string) sarif.Report {
	return sarif.Report{Results: []sarif.Result{{Level: level, Priority: priority}}}
}

func TestPriorityGateFailsBelowLevelThreshold(t *testing.T) {
	// A note-level finding would pass a fail-on-error level gate, but its P1 priority trips
	// the priority gate — component-aware gating in action.
	p := Policy{FailOn: sarif.SeverityHigh, FailOnPriority: "P2"}
	res := p.Evaluate(map[string]sarif.Report{
		"images": reportWithPriority(sarif.LevelNote, "P1"),
	})
	if res.Verdict != Fail {
		t.Fatalf("verdict = %s, want fail (P1 >= P2 gate)", res.Verdict)
	}
	if res.Controls[0].HighestPriority != "P1" {
		t.Errorf("highestPriority = %q, want P1", res.Controls[0].HighestPriority)
	}
}

func TestPriorityGatePassesWhenBelowBand(t *testing.T) {
	// P3 finding, gate at P1: priority gate does not trip; note level passes too.
	p := Policy{FailOn: sarif.SeverityHigh, FailOnPriority: "P1"}
	res := p.Evaluate(map[string]sarif.Report{
		"sast": reportWithPriority(sarif.LevelNote, "P3"),
	})
	if res.Verdict != Pass {
		t.Fatalf("verdict = %s, want pass", res.Verdict)
	}
}

func TestPriorityGateDisabledByDefault(t *testing.T) {
	// Without FailOnPriority, a P1 finding at note level still passes a fail-on-error gate.
	p := Policy{FailOn: sarif.SeverityHigh}
	res := p.Evaluate(map[string]sarif.Report{
		"sast": reportWithPriority(sarif.LevelNote, "P1"),
	})
	if res.Verdict != Pass {
		t.Fatalf("verdict = %s, want pass (priority gate off)", res.Verdict)
	}
	// HighestPriority is still reported as evidence.
	if res.Controls[0].HighestPriority != "P1" {
		t.Errorf("highestPriority = %q, want P1", res.Controls[0].HighestPriority)
	}
}

func TestVerdictIgnoresSuppressedFindings(t *testing.T) {
	// The end of the chain: an excluded finding must not fail the build, on level or priority.
	rep := sarif.Report{Results: []sarif.Result{{
		RuleID: "private-key", Level: sarif.LevelError, Priority: "P1",
		Suppression: &sarif.Suppression{Kind: "external", Justification: "fixture"},
	}}}
	p := Policy{FailOn: sarif.SeverityHigh, FailOnPriority: "P1"}
	res := p.Evaluate(map[string]sarif.Report{"secrets": rep})
	if res.Verdict != Pass {
		t.Errorf("verdict = %v, want Pass — the only finding is suppressed", res.Verdict)
	}
	if res.Controls[0].HighestPriority != "" {
		t.Errorf("HighestPriority = %q, want empty", res.Controls[0].HighestPriority)
	}
}

func TestVerdictStillFailsOnAnUnsuppressedFinding(t *testing.T) {
	rep := sarif.Report{Results: []sarif.Result{
		{RuleID: "a", Level: sarif.LevelError, Suppression: &sarif.Suppression{Kind: "external", Justification: "x"}},
		{RuleID: "b", Level: sarif.LevelError},
	}}
	res := Policy{FailOn: sarif.SeverityHigh}.Evaluate(map[string]sarif.Report{"sca": rep})
	if res.Verdict != Fail {
		t.Error("an unsuppressed error must still fail the gate")
	}
}

// Go randomizes map iteration, so an Evaluate that returned controls in map order would order
// them differently on every run — reaching the console, report.json, and the markdown and HTML
// reports, and making two scans of an unchanged repository diff against each other.
//
// Asserted directly rather than by evaluating twice and comparing: with a handful of controls,
// two runs collide by chance often enough that such a test would pass most of the time and fail
// mysteriously the rest.
func TestEvaluateOrdersControlsAlphabetically(t *testing.T) {
	reports := map[string]sarif.Report{
		"secrets":  {},
		"iac":      {},
		"sca":      {},
		"licenses": {},
		"sast":     {},
	}
	res := Policy{FailOn: sarif.SeverityHigh}.Evaluate(reports)

	got := make([]string, 0, len(res.Controls))
	for _, c := range res.Controls {
		got = append(got, c.Control)
	}
	want := []string{"iac", "licenses", "sast", "sca", "secrets"}
	if !slices.Equal(got, want) {
		t.Errorf("control order = %v, want %v", got, want)
	}
}

// TestGateJudgesTheBandTheReportPrints is the reason thresholds are severities.
//
// A finding carrying a CVSS score takes its band from the score, not from the level the scanner
// wrote. Real scanners emit high-scoring findings as `warning` — a 7.8 sandbox breakout among
// them — so a gate comparing levels passed a finding the report beside it called `high`. The
// verdict and the page have to agree about the same finding.
func TestGateJudgesTheBandTheReportPrints(t *testing.T) {
	// Level says warning; the score says 7.8, so the band is high.
	scored := sarif.Report{Results: []sarif.Result{{
		RuleID: "CVE-2024-56326", Level: sarif.LevelWarning, HasScore: true, Score: 7.8,
	}}}
	if got := scored.HighestSeverity(); got != sarif.SeverityHigh {
		t.Fatalf("the fixture does not reproduce the case: band is %q", got)
	}

	res := Policy{FailOn: sarif.SeverityHigh}.Evaluate(map[string]sarif.Report{"sca": scored})
	if res.Verdict != Fail {
		t.Error("a high-severity finding did not fail a gate set to high")
	}

	// And the band still decides when it points the other way: a finding the scanner called an
	// error but scored as medium is a medium, and a gate set to high lets it through.
	lowScored := sarif.Report{Results: []sarif.Result{{
		RuleID: "KSV-0001", Level: sarif.LevelError, HasScore: true, Score: 5.5,
	}}}
	if got := (Policy{FailOn: sarif.SeverityHigh}).Evaluate(
		map[string]sarif.Report{"iac": lowScored}); got.Verdict != Pass {
		t.Error("a medium-severity finding failed a gate set to high")
	}
}
