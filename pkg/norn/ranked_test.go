package norn

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The three findings a severity gate used to misjudge, as the prioritizer records them: a CVE
// scored high and raised by KEV, a secret its scanner rated medium and held at high by the
// control's floor, and a critical CVE an unreachable verdict lowered to high. Each is P1 or P2 as
// the band that came from its ranked severity says.
var (
	kevRaised = sarif.Result{
		RuleID: "CVE-2021-44228", Level: sarif.LevelError, Score: 7.5, HasScore: true, Priority: "P1",
		Escalation: &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical, Signal: "kev", Detail: "on KEV"},
	}
	flooredSecret = sarif.Result{
		RuleID: "generic-api-key", Level: sarif.LevelWarning, Priority: "P1", SeverityFloor: sarif.SeverityHigh,
	}
	unreachableCritical = sarif.Result{
		RuleID: "CVE-2099-0001", Level: sarif.LevelError, Score: 9.8, HasScore: true, Priority: "P2",
		Reachability: &sarif.Reachability{
			State: sarif.ReachabilityUnreachable, Method: sarif.MethodCallGraph, RankedAs: sarif.SeverityHigh,
		},
	}
)

// A severity gate judges the severity the report prints beside the band, in both directions, and
// FindingFails agrees with Evaluate on every one of them.
func TestASeverityGateJudgesTheRankedSeverity(t *testing.T) {
	for _, c := range []struct {
		name    string
		control string
		res     sarif.Result
		failOn  sarif.Severity
		fails   bool
		highest sarif.Severity
	}{
		{"raised by KEV, --fail-on critical", "sca", kevRaised, sarif.SeverityCritical, true, sarif.SeverityCritical},
		{"held at the floor, --fail-on high", "secrets", flooredSecret, sarif.SeverityHigh, true, sarif.SeverityHigh},
		{"held at the floor, --fail-on critical", "secrets", flooredSecret, sarif.SeverityCritical, false, sarif.SeverityHigh},
		{"lowered as unreachable, --fail-on critical", "sca", unreachableCritical, sarif.SeverityCritical, false, sarif.SeverityHigh},
		{"lowered as unreachable, --fail-on high", "sca", unreachableCritical, sarif.SeverityHigh, true, sarif.SeverityHigh},
	} {
		p := Policy{FailOn: c.failOn}
		got := p.Evaluate(map[string]sarif.Report{c.control: {Results: []sarif.Result{c.res}}})
		if (got.Verdict == Fail) != c.fails {
			t.Errorf("%s: verdict %s, want fail = %v", c.name, got.Verdict, c.fails)
		}
		if h := got.Controls[0].Highest; h != c.highest {
			t.Errorf("%s: highest %q, want %q", c.name, h, c.highest)
		}
		if ff := p.FindingFails(c.control, c.res); ff != c.fails {
			t.Errorf("%s: FindingFails = %v, want %v", c.name, ff, c.fails)
		}
	}
}

// A per-control severity threshold reads the same value as the run-wide one.
func TestAPerControlSeverityJudgesTheRankedSeverity(t *testing.T) {
	p := Policy{FailOn: sarif.SeverityCritical, PerControl: map[string]sarif.Severity{"secrets": sarif.SeverityHigh}}
	got := p.Evaluate(map[string]sarif.Report{
		"secrets": {Results: []sarif.Result{flooredSecret}},
		"sca":     {Results: []sarif.Result{unreachableCritical}},
	})
	verdicts := map[string]Verdict{}
	for _, c := range got.Controls {
		verdicts[c.Control] = c.Verdict
	}
	if verdicts["secrets"] != Fail {
		t.Errorf("secrets = %s; a secret held at high fails its own high threshold", verdicts["secrets"])
	}
	if verdicts["sca"] != Pass {
		t.Errorf("sca = %s; a critical lowered to high passes critical", verdicts["sca"])
	}
}

// The band gate reads the band, and none of the three moves changes its verdict.
func TestTheBandGateIsUnchangedByTheMoves(t *testing.T) {
	for _, c := range []struct {
		name  string
		res   sarif.Result
		fails bool
	}{
		{"raised by KEV", kevRaised, true},
		{"held at the floor", flooredSecret, true},
		{"lowered as unreachable", unreachableCritical, false},
	} {
		got := Policy{}.Evaluate(map[string]sarif.Report{"sca": {Results: []sarif.Result{c.res}}})
		if (got.Verdict == Fail) != c.fails {
			t.Errorf("%s: P1 gate verdict %s, want fail = %v", c.name, got.Verdict, c.fails)
		}
		// The same finding with its moves stripped lands in the same band, so the band gate gives
		// the same answer: what changed is only what a severity gate reads.
		bare := c.res
		bare.Escalation, bare.Reachability, bare.SeverityFloor = nil, nil, ""
		if again := (Policy{}).Evaluate(map[string]sarif.Report{"sca": {Results: []sarif.Result{bare}}}); again.Verdict != got.Verdict {
			t.Errorf("%s: P1 gate verdict moved from %s to %s with the moves stripped", c.name, again.Verdict, got.Verdict)
		}
	}
}
