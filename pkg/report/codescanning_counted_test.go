package report

import (
	"encoding/json"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The code-scanning report, which the Action hands to upload-sarif on a push, holds a flaw two
// scanners reported once, under the finding the gate counted, which names the other scanner. The
// sarif report from the same run keeps both scanners' findings.
func TestBuildCodeScanningHoldsOneResultPerCountedFinding(t *testing.T) {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-2020-11023", Tool: "trivy", Level: sarif.LevelError, Priority: "P1",
				Location:    sarif.Location{URI: "web/package-lock.json", StartLine: 10},
				Correlation: &sarif.Correlation{AlsoFoundBy: []sarif.Observation{{Tool: "retirejs", Severity: sarif.SeverityMedium}}}},
			{RuleID: "CVE-2020-11023", Tool: "retirejs", Level: sarif.LevelError, Priority: "P1",
				Location:    sarif.Location{URI: "web/static/js/jquery.min.js"},
				Correlation: &sarif.Correlation{CountedUnder: "trivy"}},
		}}},
	}}
	data := Data{Project: "app", Run: run, Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
		{Control: "sca", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1}},
	}}}
	toolsIn := func(format string) []string {
		t.Helper()
		a, err := Build(saga.ReportConfig{Format: format}, data)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []struct {
				Results []struct {
					Properties struct {
						Tool string `json:"tool"`
					} `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(a.Bytes, &doc); err != nil {
			t.Fatalf("%s is not SARIF: %v", format, err)
		}
		var tools []string
		for _, r := range doc.Runs {
			for _, res := range r.Results {
				tools = append(tools, res.Properties.Tool)
			}
		}
		return tools
	}
	if got := toolsIn(CodeScanningFormat); len(got) != 1 || got[0] != "trivy" {
		t.Errorf("code-scanning holds results from %q, want trivy's counted finding alone", got)
	}
	if got := toolsIn("sarif"); len(got) != 2 {
		t.Errorf("sarif holds results from %q, want both scanners' findings", got)
	}
}
