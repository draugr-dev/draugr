package skald

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding a supplier's VEX claim excused says, in report.json as in results.sarif, whose claim it
// was and exactly which: the document, the statement within it and the digest of the bytes read. A
// policy trusting one supplier's documents and not another's reads these, and a rule this project
// wrote carries none of them.
func TestAnImportedSuppressionNamesItsDocumentAndStatement(t *testing.T) {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P2", Suppression: &sarif.Suppression{
				Kind: "external", Justification: "vulnerable_code_not_in_execute_path", Origin: sarif.OriginVEX,
				Author: "Acme Ltd", Asserted: "2026-08-01T09:00:00Z", Source: "vendor/acme.json",
				StatementID: "https://acme.example/vex/stmt-1", Digest: "sha256:aaaa",
			}},
			{RuleID: "CVE-2", Level: sarif.LevelError, Priority: "P2", Suppression: &sarif.Suppression{
				Kind: "external", Justification: "a test fixture", Origin: sarif.OriginSaga,
			}},
		}}},
	}}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Version: "1"}, run, sampleVerdict(), "P4"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			RuleID     string            `json:"ruleId"`
			Suppressed map[string]string `json:"suppressed"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	by := map[string]map[string]string{}
	for _, f := range doc.Findings {
		by[f.RuleID] = f.Suppressed
	}
	want := map[string]string{
		"origin": "vex", "author": "Acme Ltd", "asserted": "2026-08-01T09:00:00Z", "source": "vendor/acme.json",
		"statementId": "https://acme.example/vex/stmt-1", "digest": "sha256:aaaa",
	}
	for k, v := range want {
		if by["CVE-1"][k] != v {
			t.Errorf("the VEX suppression's %s = %q, want %q", k, by["CVE-1"][k], v)
		}
	}
	for _, k := range []string{"author", "asserted", "statementId", "digest"} {
		if v, ok := by["CVE-2"][k]; ok {
			t.Errorf("the project's own rule carries %s = %q, which only an imported claim has", k, v)
		}
	}
}
