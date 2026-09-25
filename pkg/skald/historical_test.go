package skald

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// TestReportJSONFindingSaysItIsHistorical holds the history mark in report.json. A history
// finding's location is the path its file had in an old commit, and without the mark a consumer
// reads a path the checkout lacks as a finding already fixed.
func TestReportJSONFindingSaysItIsHistorical(t *testing.T) {
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{"secrets": {Control: "secrets", Report: sarif.Report{
			Tool: "gitleaks", Results: []sarif.Result{{
				RuleID: "aws-access-token", Level: sarif.LevelError, Priority: "P1",
				Component: "api", Repository: "./api",
				Location:   sarif.Location{URI: "old/aws.env", StartLine: 1},
				Historical: true,
			}, {
				RuleID: "generic-api-key", Level: sarif.LevelError, Priority: "P1",
				Component: "web", Repository: "./web",
				Location: sarif.Location{URI: "settings.py", StartLine: 3},
			}},
		}}},
	}
	findings, ok := renderJSON(t, run, "P4")["findings"].([]any)
	if !ok || len(findings) != 2 {
		t.Fatalf("findings = %v", findings)
	}
	byLocation := map[string]map[string]any{}
	for _, f := range findings {
		m := f.(map[string]any)
		byLocation[m["location"].(string)] = m
	}
	if byLocation["old/aws.env:1"]["historical"] != true {
		t.Errorf("the history finding is not marked historical: %v", byLocation["old/aws.env:1"])
	}
	if _, present := byLocation["settings.py:3"]["historical"]; present {
		t.Errorf("a tree finding carries the history mark: %v", byLocation["settings.py:3"])
	}
}
