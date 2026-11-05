package sarif

import (
	"strings"
	"testing"
)

// Each move the prioritizer records, read back in the order it applies them.
func TestRankedSeverityReadsEveryMove(t *testing.T) {
	unreachable := func(rankedAs Severity) *Reachability {
		return &Reachability{State: ReachabilityUnreachable, Method: MethodCallGraph, RankedAs: rankedAs}
	}
	for _, c := range []struct {
		name string
		res  Result
		want Severity
	}{
		{"the level", Result{Level: LevelWarning}, SeverityMedium},
		{"the score", Result{Level: LevelNote, Score: 9.8, HasScore: true}, SeverityCritical},
		{"the scanner's rating", Result{Level: LevelError, Rating: &Rating{Severity: SeverityLow}}, SeverityLow},
		{"held at the floor", Result{Level: LevelWarning, SeverityFloor: SeverityHigh}, SeverityHigh},
		{"a floor below the rating", Result{Level: LevelError, Score: 9.5, HasScore: true, SeverityFloor: SeverityHigh}, SeverityCritical},
		{"raised", Result{Level: LevelError, Escalation: &Escalation{From: SeverityHigh, To: SeverityCritical, Signal: "kev"}}, SeverityCritical},
		{"raised from the floor", Result{Level: LevelNote, SeverityFloor: SeverityHigh, Escalation: &Escalation{From: SeverityHigh, To: SeverityCritical, Signal: "kev"}}, SeverityCritical},
		{"lowered", Result{Level: LevelNote, Score: 9.8, HasScore: true, Reachability: unreachable(SeverityHigh)}, SeverityHigh},
		{"raised, then lowered", Result{
			Level: LevelNote, Score: 2.0, HasScore: true,
			Escalation:   &Escalation{From: SeverityLow, To: SeverityMedium, Signal: "deprecated"},
			Reachability: unreachable(SeverityLow),
		}, SeverityLow},
		{"an unreachable verdict that moved nothing", Result{Level: LevelError, Reachability: unreachable("")}, SeverityHigh},
		{"a reachable verdict", Result{Level: LevelError, Reachability: &Reachability{State: ReachabilityReachable, RankedAs: SeverityLow}}, SeverityHigh},
		{"an escalation with no target", Result{Level: LevelWarning, Escalation: &Escalation{Signal: "kev"}}, SeverityMedium},
	} {
		if got := c.res.RankedSeverity(); got != c.want {
			t.Errorf("%s: RankedSeverity = %q, want %q", c.name, got, c.want)
		}
	}
}

// The gate's highest is the worst ranked severity, in both directions: a raised finding lifts it
// and a lowered one no longer holds it up. A suppressed finding is not judged.
func TestHighestSeverityIsTheWorstRankedSeverity(t *testing.T) {
	raised := Result{RuleID: "CVE-1", Level: LevelError, Score: 7.5, HasScore: true,
		Escalation: &Escalation{From: SeverityHigh, To: SeverityCritical, Signal: "kev"}}
	lowered := Result{RuleID: "CVE-2", Level: LevelError, Score: 9.8, HasScore: true,
		Reachability: &Reachability{State: ReachabilityUnreachable, Method: MethodCallGraph, RankedAs: SeverityHigh}}
	floored := Result{RuleID: "token", Level: LevelWarning, SeverityFloor: SeverityHigh}
	suppressed := Result{RuleID: "CVE-3", Level: LevelError, Score: 9.9, HasScore: true,
		Suppression: &Suppression{Justification: "accepted"}}

	for _, c := range []struct {
		name string
		rep  Report
		want Severity
	}{
		{"raised", Report{Results: []Result{raised}}, SeverityCritical},
		{"lowered", Report{Results: []Result{lowered}}, SeverityHigh},
		{"floored", Report{Results: []Result{floored}}, SeverityHigh},
		{"suppressed", Report{Results: []Result{suppressed, floored}}, SeverityHigh},
		{"nothing", Report{}, ""},
	} {
		if got := c.rep.HighestSeverity(); got != c.want {
			t.Errorf("%s: HighestSeverity = %q, want %q", c.name, got, c.want)
		}
	}
}

// The floor survives results.sarif, alone if need be, so a gate on new findings reading the file
// judges the severity the run did.
func TestTheSeverityFloorSurvivesTheFile(t *testing.T) {
	rep := Report{Results: []Result{{RuleID: "token", Level: LevelWarning, Message: "a credential", SeverityFloor: SeverityHigh}}}
	encoded, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"severityFloor": "high"`) {
		t.Fatalf("the floor was dropped on the way out:\n%s", encoded)
	}
	back, err := FromSARIF(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != 1 {
		t.Fatalf("read back %d results", len(back.Results))
	}
	if got := back.Results[0].RankedSeverity(); got != SeverityHigh {
		t.Errorf("RankedSeverity read back = %q, want high", got)
	}
}
