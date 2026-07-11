package sarif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalSARIFStructure(t *testing.T) {
	r := Report{Tool: "trivy", Results: []Result{
		{RuleID: "CVE-1", Level: LevelError, Message: "boom", Location: Location{URI: "img", StartLine: 5}},
	}}
	data, err := r.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	// Must be valid JSON with the SARIF shape.
	var log map[string]any
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if log["version"] != Version {
		t.Errorf("version = %v", log["version"])
	}
	if !strings.Contains(string(data), "\"$schema\"") || !strings.Contains(string(data), "artifactLocation") {
		t.Errorf("missing SARIF fields:\n%s", data)
	}
}

func TestSARIFRoundTrip(t *testing.T) {
	orig := Report{Results: []Result{
		{Tool: "trivy", RuleID: "CVE-1", Level: LevelError, Message: "boom", Location: Location{URI: "img", StartLine: 5}},
		{Tool: "grype", RuleID: "CVE-2", Level: LevelWarning, Message: "meh"},
	}}
	data, err := orig.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 2 {
		t.Fatalf("round-trip results = %d, want 2", len(got.Results))
	}
	// Multi-tool grouping preserves per-result tool.
	tools := map[string]bool{}
	for _, res := range got.Results {
		tools[res.Tool] = true
	}
	if !tools["trivy"] || !tools["grype"] {
		t.Errorf("tools not preserved: %v", tools)
	}
	// Location round-trips.
	for _, res := range got.Results {
		if res.RuleID == "CVE-1" && (res.Location.URI != "img" || res.Location.StartLine != 5) {
			t.Errorf("location lost: %+v", res.Location)
		}
	}
}

// Some tools (e.g. Gitleaks) emit results with no "level". SARIF 2.1.0 says such a result
// defaults to "warning" when there's no rule configuration to say otherwise.
func TestFromSARIFDefaultsAbsentLevelToWarning(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "gitleaks"}},
			"results": [{"ruleId": "aws-key", "message": {"text": "leaked key"}}]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(got.Results))
	}
	if got.Results[0].Level != LevelWarning {
		t.Errorf("absent level = %q, want warning", got.Results[0].Level)
	}
}

func TestFromSARIFInvalid(t *testing.T) {
	if _, err := FromSARIF([]byte("{not json")); err == nil {
		t.Fatal("expected error")
	}
}

func TestMarshalEmptyReport(t *testing.T) {
	data, err := Report{}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 0 {
		t.Errorf("empty report should round-trip to zero results, got %d", len(got.Results))
	}
}
