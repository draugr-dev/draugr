package skald

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding listed in report.json carries the rating its severity came from beside the level the
// scanner wrote, so a consumer holding a P1 on an `error` can say what put it there.
func TestReportJSONFindingCarriesTheScannersRating(t *testing.T) {
	run := engine.Result{Controls: map[string]plugin.ControlResult{"sast": {Control: "sast", Report: sarif.Report{
		Tool: "semgrep", Results: []sarif.Result{{
			RuleID: "python.lang.security.dangerous-system-call.dangerous-system-call", Level: sarif.LevelError, Priority: "P1",
			Rating: &sarif.Rating{
				Severity: sarif.SeverityCritical, Detail: "impact high · likelihood high",
				Fields: map[string]string{"impact": "HIGH", "likelihood": "HIGH"},
			},
		}},
	}}}}
	findings, ok := renderJSON(t, run, "P4")["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings = %v", findings)
	}
	f := findings[0].(map[string]any)
	rating, ok := f["rating"].(map[string]any)
	if !ok {
		t.Fatalf("no rating on %v", f)
	}
	if f["level"] != "error" || rating["severity"] != "critical" || rating["detail"] != "impact high · likelihood high" {
		t.Errorf("finding = %v", f)
	}
	if fields, _ := rating["fields"].(map[string]any); fields["impact"] != "HIGH" {
		t.Errorf("fields = %v, want Semgrep's own words", rating["fields"])
	}
}
