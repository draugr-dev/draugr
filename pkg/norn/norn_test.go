package norn

import (
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
	if res.Controls[0].Highest != sarif.LevelError {
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
	p := Policy{FailOn: sarif.LevelNote} // strict threshold
	res := p.Evaluate(map[string]sarif.Report{"images": {}})
	if res.Verdict != Pass {
		t.Fatalf("empty report should pass, got %s", res.Verdict)
	}
}

func TestPerControlOverride(t *testing.T) {
	p := Policy{
		FailOn:     sarif.LevelError,
		PerControl: map[string]sarif.Level{"headers": sarif.LevelWarning},
	}
	res := p.Evaluate(map[string]sarif.Report{
		"headers": report(sarif.LevelWarning), // fails under stricter per-control threshold
	})
	if res.Verdict != Fail {
		t.Fatalf("verdict = %s, want fail (per-control threshold)", res.Verdict)
	}
	if res.Controls[0].Threshold != sarif.LevelWarning {
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
	p := Policy{FailOn: sarif.LevelWarning, PerControl: map[string]sarif.Level{"x": ""}}
	if got := p.thresholdFor("x"); got != sarif.LevelWarning {
		t.Errorf("thresholdFor empty override = %s, want warning", got)
	}
	if got := p.thresholdFor("unknown"); got != sarif.LevelWarning {
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
	p := Policy{FailOn: sarif.LevelError, FailOnPriority: "P2"}
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
	p := Policy{FailOn: sarif.LevelError, FailOnPriority: "P1"}
	res := p.Evaluate(map[string]sarif.Report{
		"sast": reportWithPriority(sarif.LevelNote, "P3"),
	})
	if res.Verdict != Pass {
		t.Fatalf("verdict = %s, want pass", res.Verdict)
	}
}

func TestPriorityGateDisabledByDefault(t *testing.T) {
	// Without FailOnPriority, a P1 finding at note level still passes a fail-on-error gate.
	p := Policy{FailOn: sarif.LevelError}
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
