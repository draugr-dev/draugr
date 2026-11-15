package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// twoTrivies holds a finding from each of the two scanners that run Trivy, named by the tool as
// each writes it, and one imported from another tool's SARIF.
func twoTrivies() Data {
	at := func(control, tool, scanner, rule, uri string) sarif.Result {
		return sarif.Result{Tool: tool, Scanner: scanner, RuleID: rule, Level: sarif.LevelWarning, Message: "m",
			Control: control, Priority: "P2", Location: sarif.Location{URI: uri, StartLine: 3}}
	}
	return Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"iac":  {Report: sarif.Report{Results: []sarif.Result{at("iac", "Trivy", "trivy-config", "KSV-0041", "deploy/rbac.yaml")}}},
		"sca":  {Report: sarif.Report{Results: []sarif.Result{at("sca", "trivy", "trivy-fs", "CVE-2026-1", "go.mod")}}},
		"sast": {Report: sarif.Report{Results: []sarif.Result{at("sast", "Bandit", plugin.ImportScanner, "B101", "app.py")}}},
	}}}
}

// The HTML report names a finding's scanner by Draugr's name for it, so the two scanners that run
// Trivy are two filter entries rather than one tool spelled two ways, and an imported finding by its
// tool's own name rather than the import's. The console is unchanged and prints the tool, lowercased.
func TestTheHTMLReportNamesDraugrsScanner(t *testing.T) {
	listed := twoTrivies()
	listed.MinPriority = "P4"
	var buf bytes.Buffer
	if err := (htmlReporter{}).Render(&buf, listed); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	for _, want := range []string{`value="trivy-config"`, `value="trivy-fs"`, `value="Bandit"`, `data-sc="trivy-config"`} {
		if !strings.Contains(html, want) {
			t.Errorf("the HTML report does not hold %s", want)
		}
	}
	for _, unwanted := range []string{`value="Trivy"`, `value="trivy"`, `sarif-import`} {
		if strings.Contains(html, unwanted) {
			t.Errorf("the HTML report holds %s", unwanted)
		}
	}

	buf.Reset()
	if err := (consoleReporter{}).Render(&buf, twoTrivies()); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "scanner trivy ·") != 2 || strings.Contains(buf.String(), "trivy-config") {
		t.Errorf("the console changed its scanner word:\n%s", buf.String())
	}

	buf.Reset()
	if err := (jsonReporter{}).Render(&buf, listed); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			RuleID  string `json:"ruleId"`
			Tool    string `json:"tool"`
			Scanner string `json:"scanner"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range doc.Findings {
		got[f.RuleID] = f.Tool + "/" + f.Scanner
	}
	if got["KSV-0041"] != "Trivy/trivy-config" || got["CVE-2026-1"] != "trivy/trivy-fs" {
		t.Errorf("report.json tool/scanner by rule = %v", got)
	}
}

// The scanner survives results.sarif, and it is not part of a finding's identity, so a finding
// recorded before the field existed is the same finding.
func TestTheScannerSurvivesTheSARIFFileAndLeavesTheFingerprint(t *testing.T) {
	r := sarif.Result{Tool: "Trivy", Scanner: "trivy-config", RuleID: "KSV-0041", Level: sarif.LevelWarning, Message: "m",
		Location: sarif.Location{URI: "deploy/rbac.yaml", StartLine: 3}}
	raw, err := sarif.Report{Tool: "Trivy", Results: []sarif.Result{r}}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sarif.FromSARIF(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Results[0].Scanner; got != "trivy-config" {
		t.Errorf("read back scanner %q", got)
	}
	older := r
	older.Scanner = ""
	if r.Fingerprint() != older.Fingerprint() {
		t.Error("the scanner moved the fingerprint")
	}
}
