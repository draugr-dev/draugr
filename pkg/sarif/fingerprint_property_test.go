package sarif

import (
	"encoding/json"
	"testing"
)

// TestEachResultCarriesItsFingerprint: report.json names the findings an action clears by
// fingerprint, and a reader joins them to results.sarif on this property without having to know
// how the value is computed.
func TestEachResultCarriesItsFingerprint(t *testing.T) {
	res := Result{RuleID: "CVE-2020-11023", Level: LevelError, Tool: "trivy", Control: "sca",
		Component: "web", Repository: "https://github.com/acme/web",
		Location: Location{URI: "package-lock.json", StartLine: 12}}
	data, err := (Report{Results: []Result{res}}).MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.Runs[0].Results[0].Properties["fingerprint"]; got != res.Fingerprint() {
		t.Errorf("properties.fingerprint = %v, want %s", got, res.Fingerprint())
	}
}
