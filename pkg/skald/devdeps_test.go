package skald

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding in a development dependency says so in report.json, and one the setting set aside stays
// in the list suppressed, with the reason and the key that decided. A runtime finding carries
// neither.
func TestReportJSONFindingSaysItIsADevelopmentDependency(t *testing.T) {
	nanoid := &sarif.Package{Name: "nanoid", Version: "3.3.7", PURL: "pkg:npm/nanoid@3.3.7", Dev: true}
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
			Tool: "trivy", Results: []sarif.Result{{
				RuleID: "CVE-2026-67213", Level: sarif.LevelError, Priority: "P1", Component: "web",
				Location: sarif.Location{URI: "npm/package-lock.json", StartLine: 23}, Package: nanoid,
				Suppression: &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting,
					Justification: sarif.JustificationDevDependency, Source: "config.controls.sca.devDependencies"},
			}, {
				RuleID: "CVE-2021-23337", Level: sarif.LevelError, Priority: "P1", Component: "web",
				Location: sarif.Location{URI: "npm/package-lock.json", StartLine: 17},
				Package:  &sarif.Package{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"},
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
	dev := byLocation["npm/package-lock.json:23"]
	if dev["dev"] != true {
		t.Errorf("the development finding is not marked dev: %v", dev)
	}
	sup, _ := dev["suppressed"].(map[string]any)
	if sup["origin"] != "setting" || sup["justification"] != "development dependency" ||
		sup["source"] != "config.controls.sca.devDependencies" {
		t.Errorf("suppressed = %v, want the setting, its reason and its key", sup)
	}
	runtime := byLocation["npm/package-lock.json:17"]
	if _, present := runtime["dev"]; present {
		t.Errorf("a runtime finding carries the dev mark: %v", runtime)
	}
	if _, present := runtime["suppressed"]; present {
		t.Errorf("a runtime finding is suppressed: %v", runtime)
	}
}
