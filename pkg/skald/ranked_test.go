package skald

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// report.json states the severity each control was judged on, and each finding carries the floor
// that held it, so a reader can check a severity gate's verdict against the rows.
func TestReportJSONStatesTheSeverityEachControlWasJudgedOn(t *testing.T) {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{{
			RuleID: "CVE-2021-44228", Level: sarif.LevelError, Score: 7.5, HasScore: true, Priority: "P1",
			Escalation: &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical, Signal: "kev"},
		}}}},
		"secrets": {Control: "secrets", Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{{
			RuleID: "generic-api-key", Level: sarif.LevelWarning, Priority: "P1", SeverityFloor: sarif.SeverityHigh,
		}}}},
	}}
	policy := norn.Policy{FailOn: sarif.SeverityHigh}
	reports := map[string]sarif.Report{}
	for name, cr := range run.Controls {
		reports[name] = cr.Report
	}
	verdict := policy.Evaluate(reports)

	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Version: "1"}, run, verdict, "P4"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Verdict  string
		Controls []struct{ Name, Verdict, Highest, Threshold string }
		Findings []struct {
			RuleID        string `json:"ruleId"`
			SeverityFloor string `json:"severityFloor"`
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"sca": "critical", "secrets": "high"}
	for _, c := range doc.Controls {
		if c.Highest != want[c.Name] {
			t.Errorf("%s: highest %q, want %q", c.Name, c.Highest, want[c.Name])
		}
		if c.Verdict != "fail" || c.Threshold != "high" {
			t.Errorf("%s: verdict %q at threshold %q, want fail at high", c.Name, c.Verdict, c.Threshold)
		}
	}
	floors := map[string]string{}
	for _, f := range doc.Findings {
		floors[f.RuleID] = f.SeverityFloor
	}
	if floors["generic-api-key"] != "high" || floors["CVE-2021-44228"] != "" {
		t.Errorf("severityFloor = %v, want high on the secret and nothing on the CVE", floors)
	}
}
