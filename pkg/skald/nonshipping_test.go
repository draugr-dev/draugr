package skald

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Each finding under docs, examples or tests names the kind of directory in report.json, over two
// components in two repositories, counted or set aside. A finding in shipped code carries nothing.
func TestReportJSONFindingNamesItsNonShippingDirectory(t *testing.T) {
	at := func(component, repo, uri, mark string) sarif.Result {
		return sarif.Result{RuleID: "DS-0002", Level: sarif.LevelError, Priority: "P1", Component: component,
			Repository: repo, Location: sarif.Location{URI: uri, StartLine: 1}, NonShipping: mark}
	}
	setAside := at("web", "https://example.test/web.git", "docs/Dockerfile", "docs")
	setAside.Suppression = &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting,
		Justification: sarif.JustificationNonShipping, Source: "config.controls.iac.nonShippingPaths"}
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{"iac": {Control: "iac", Report: sarif.Report{
			Tool: "trivy", Results: []sarif.Result{
				at("api", "https://example.test/api.git", "tests/Dockerfile", "test"),
				at("api", "https://example.test/api.git", "Dockerfile", ""),
				setAside,
			},
		}}},
	}
	findings, ok := renderJSON(t, run, "P4")["findings"].([]any)
	if !ok || len(findings) != 3 {
		t.Fatalf("findings = %v", findings)
	}
	byLocation := map[string]map[string]any{}
	for _, f := range findings {
		m := f.(map[string]any)
		byLocation[m["location"].(string)] = m
	}
	if got := byLocation["tests/Dockerfile:1"]["nonShipping"]; got != "test" {
		t.Errorf("tests/Dockerfile nonShipping = %v, want test", got)
	}
	docs := byLocation["docs/Dockerfile:1"]
	if docs["nonShipping"] != "docs" {
		t.Errorf("docs/Dockerfile nonShipping = %v, want docs", docs["nonShipping"])
	}
	if sup, _ := docs["suppressed"].(map[string]any); sup["justification"] != "in docs, examples or tests" ||
		sup["source"] != "config.controls.iac.nonShippingPaths" {
		t.Errorf("suppressed = %v, want the setting's reason and key", sup)
	}
	if _, present := byLocation["Dockerfile:1"]["nonShipping"]; present {
		t.Errorf("a finding in shipped code carries the mark: %v", byLocation["Dockerfile:1"])
	}
}
