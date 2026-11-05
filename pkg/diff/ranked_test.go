package diff

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The gate on new findings judges the severity the scan's own gate judges, read from what
// results.sarif recorded, so a raised finding trips --fail-on-new critical and a lowered one does
// not. Two repositories, so a value collapsed across them cannot pass.
func TestGateNewJudgesTheRankedSeverity(t *testing.T) {
	raised := sarif.Result{
		Tool: "trivy", RuleID: "CVE-2021-44228", Level: sarif.LevelError, Score: 7.5, HasScore: true,
		Location: sarif.Location{URI: "go.mod"}, Repository: "https://example.com/a.git", Priority: "P1",
		Escalation: &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical, Signal: "kev"},
	}
	lowered := sarif.Result{
		Tool: "trivy", RuleID: "CVE-2099-0001", Level: sarif.LevelError, Score: 9.8, HasScore: true,
		Location: sarif.Location{URI: "go.mod"}, Repository: "https://example.com/b.git", Priority: "P2",
		Reachability: &sarif.Reachability{
			State: sarif.ReachabilityUnreachable, Method: sarif.MethodCallGraph, RankedAs: sarif.SeverityHigh,
		},
	}
	floored := sarif.Result{
		Tool: "gitleaks", RuleID: "generic-api-key", Level: sarif.LevelWarning,
		Location: sarif.Location{URI: "config.env"}, Repository: "https://example.com/b.git", Priority: "P1",
		SeverityFloor: sarif.SeverityHigh,
	}
	head := sarif.Report{Results: []sarif.Result{raised, lowered, floored}}
	// Through the file, as `draugr diff` and --base read it.
	encoded, err := head.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	read, err := sarif.FromSARIF(encoded)
	if err != nil {
		t.Fatal(err)
	}
	d := Compare(sarif.Report{}, read)

	rules := func(rs []sarif.Result) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.RuleID)
		}
		return out
	}
	if got := rules(d.GateNew(sarif.SeverityCritical, "")); len(got) != 1 || got[0] != "CVE-2021-44228" {
		t.Errorf("--fail-on-new critical tripped on %v, want only the finding KEV raised", got)
	}
	if got := d.GateNew(sarif.SeverityHigh, ""); len(got) != 3 {
		t.Errorf("--fail-on-new high tripped on %v, want all three", rules(got))
	}
	if got := countSeverities(d.New); got != (SeverityCounts{Critical: 1, High: 2}) {
		t.Errorf("new by severity = %+v, want one critical and two high", got)
	}

	// The rows print what the gate judged.
	var out bytes.Buffer
	if err := Render(&out, "markdown", d, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| P1 | critical |", "| P2 | high |", "| P1 | high |"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("markdown has no %q:\n%s", want, out.String())
		}
	}
}
