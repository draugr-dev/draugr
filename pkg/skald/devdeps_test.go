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

// A finding in a dependency the runtime provides says so in report.json, and one the setting set
// aside carries the provided reason and its key. A finding the application ships carries neither.
func TestReportJSONFindingSaysTheRuntimeProvidesIt(t *testing.T) {
	collections := &sarif.Package{Name: "commons-collections", Version: "3.2.1",
		PURL: "pkg:maven/commons-collections/commons-collections@3.2.1", Provided: true}
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
			Tool: "grype", Results: []sarif.Result{{
				RuleID: "CVE-2015-7501", Level: sarif.LevelError, Priority: "P1", Component: "shop",
				Location: sarif.Location{URI: "pom.xml", StartLine: 1}, Package: collections,
				Suppression: &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting,
					Justification: sarif.JustificationProvidedByRuntime, Source: "config.controls.sca.providedDependencies"},
			}, {
				RuleID: "CVE-2022-42889", Level: sarif.LevelError, Priority: "P1", Component: "shop",
				Location: sarif.Location{URI: "pom.xml", StartLine: 2},
				Package: &sarif.Package{Name: "commons-text", Version: "1.9",
					PURL: "pkg:maven/org.apache.commons/commons-text@1.9"},
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
	provided := byLocation["pom.xml:1"]
	if provided["provided"] != true {
		t.Errorf("the provided finding is not marked provided: %v", provided)
	}
	sup, _ := provided["suppressed"].(map[string]any)
	if sup["origin"] != "setting" || sup["justification"] != "provided by the runtime" ||
		sup["source"] != "config.controls.sca.providedDependencies" {
		t.Errorf("suppressed = %v, want the setting, its reason and its key", sup)
	}
	shipped := byLocation["pom.xml:2"]
	if _, present := shipped["provided"]; present {
		t.Errorf("a shipped finding carries the provided mark: %v", shipped)
	}
}

// A finding matched only by CPE says so in report.json, and one the setting set aside carries the
// reason and its key. A finding matched in the package's own ecosystem carries neither.
func TestReportJSONFindingSaysItWasMatchedByCPE(t *testing.T) {
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
			Tool: "grype", Results: []sarif.Result{{
				RuleID: "CVE-2022-3095-Flutter", Level: sarif.LevelError, Priority: "P1", Component: "app",
				Location: sarif.Location{URI: "ios/Podfile.lock", StartLine: 1},
				Package:  &sarif.Package{Name: "Flutter", Version: "1.0.0", Ecosystem: "pod", CPEMatch: true},
				Suppression: &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting,
					Justification: sarif.JustificationCPEMatch, Source: "config.controls.sca.cpeMatches"},
			}, {
				RuleID: "CVE-2020-35669-http", Level: sarif.LevelWarning, Priority: "P2", Component: "app",
				Location: sarif.Location{URI: "pubspec.lock", StartLine: 1},
				Package:  &sarif.Package{Name: "http", Version: "0.13.2", Ecosystem: "dart-pub"},
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
	matched := byLocation["ios/Podfile.lock:1"]
	if matched["cpeMatch"] != true {
		t.Errorf("the CPE match is not marked: %v", matched)
	}
	sup, _ := matched["suppressed"].(map[string]any)
	if sup["origin"] != "setting" || sup["justification"] != "matched by CPE only" ||
		sup["source"] != "config.controls.sca.cpeMatches" {
		t.Errorf("suppressed = %v, want the setting, its reason and its key", sup)
	}
	if _, present := byLocation["pubspec.lock:1"]["cpeMatch"]; present {
		t.Errorf("a match in the package's ecosystem carries the mark: %v", byLocation["pubspec.lock:1"])
	}
}

// A finding about the project's own package says so in report.json, with the setting's reason and
// key, and a finding about a dependency does not.
func TestReportJSONFindingSaysItIsTheProjectsOwnPackage(t *testing.T) {
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
			Tool: "grype", Results: []sarif.Result{{
				RuleID: "GHSA-69hx-wrc9-h5wq-webpack-json", Level: sarif.LevelError, Priority: "P1", Component: "site",
				Location: sarif.Location{URI: "package-lock.json", StartLine: 1},
				Package:  &sarif.Package{Name: "webpack-json", Version: "1.0.0", Ecosystem: "npm", Own: true},
				Suppression: &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting,
					Justification: sarif.JustificationOwnPackage, Source: "config.controls.sca.ownPackages"},
			}, {
				RuleID: "CVE-2021-44906-minimist", Level: sarif.LevelError, Priority: "P1", Component: "site",
				Location: sarif.Location{URI: "package-lock.json", StartLine: 9},
				Package:  &sarif.Package{Name: "minimist", Version: "1.2.5", Ecosystem: "npm"},
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
	own := byLocation["package-lock.json:1"]
	if own["own"] != true {
		t.Errorf("the project's own package is not marked: %v", own)
	}
	sup, _ := own["suppressed"].(map[string]any)
	if sup["origin"] != "setting" || sup["justification"] != "the project's own package" ||
		sup["source"] != "config.controls.sca.ownPackages" {
		t.Errorf("suppressed = %v, want the setting, its reason and its key", sup)
	}
	if _, present := byLocation["package-lock.json:9"]["own"]; present {
		t.Errorf("a dependency carries the mark: %v", byLocation["package-lock.json:9"])
	}
}

// A finding the scanner gave no location says so in report.json, and one with a location does not.
func TestReportJSONFindingSaysTheScannerGaveNoLocation(t *testing.T) {
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{"sast": {Control: "sast", Report: sarif.Report{
			Tool: "gosec", Results: []sarif.Result{
				{RuleID: "G115", Level: sarif.LevelError, Priority: "P1", Component: "api"},
				{RuleID: "G204", Level: sarif.LevelError, Priority: "P1", Component: "api",
					Location: sarif.Location{URI: "main.go", StartLine: 8}},
			},
		}}},
	}
	findings, ok := renderJSON(t, run, "P4")["findings"].([]any)
	if !ok || len(findings) != 2 {
		t.Fatalf("findings = %v", findings)
	}
	for _, f := range findings {
		m := f.(map[string]any)
		_, located := m["location"]
		if m["noLocation"] == located {
			t.Errorf("finding %v: location present %v, noLocation %v", m["ruleId"], located, m["noLocation"])
		}
	}
}
