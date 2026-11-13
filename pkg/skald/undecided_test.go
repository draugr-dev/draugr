package skald

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A benchmark check a scanner referred to a person is marked undecided in report.json, over two
// components on two clusters. A check the scanner decided carries nothing.
func TestReportJSONFindingSaysACheckWasLeftUndecided(t *testing.T) {
	check := func(component, cluster, rule string, undecided bool) sarif.Result {
		return sarif.Result{Tool: "draugr-k8s-policies", RuleID: rule, Level: sarif.LevelWarning, Priority: "P2",
			Component: component, Location: sarif.Location{URI: "kubernetes/" + cluster}, Undecided: undecided}
	}
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{"kubernetes": {Control: "kubernetes", Report: sarif.Report{
			Tool: "draugr-k8s-policies", Results: []sarif.Result{
				check("api", "staging", "draugr/cis/5.1.10", true),
				check("api", "staging", "draugr/cis/5.1.1", false),
				check("web", "production", "draugr/cis/5.1.10", true),
				check("web", "production", "draugr/cis/5.1.1", false),
			},
		}}},
	}
	findings, ok := renderJSON(t, run, "P4")["findings"].([]any)
	if !ok || len(findings) != 4 {
		t.Fatalf("findings = %v", findings)
	}
	for _, f := range findings {
		m := f.(map[string]any)
		undecided, present := m["undecided"]
		switch m["ruleId"] {
		case "draugr/cis/5.1.10":
			if undecided != true {
				t.Errorf("%v: undecided = %v, want true", m["location"], undecided)
			}
		case "draugr/cis/5.1.1":
			if present {
				t.Errorf("%v: a decided check carries the mark: %v", m["location"], m)
			}
		default:
			t.Errorf("unexpected finding %v", m)
		}
	}
}
