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

// Semgrep-style SARIF: results omit "level" and inherit it from the rule's
// defaultConfiguration. The parser must resolve the rule level (and fall back to warning
// for a result whose rule has no configured level).
func TestFromSARIFResolvesLevelFromRule(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "semgrep",
				"rules": [
					{"id": "sql-injection", "defaultConfiguration": {"level": "error"}},
					{"id": "todo-comment", "defaultConfiguration": {"level": "note"}}
				]
			}},
			"results": [
				{"ruleId": "sql-injection", "message": {"text": "tainted query"}},
				{"ruleId": "todo-comment", "message": {"text": "TODO"}},
				{"ruleId": "unknown-rule", "message": {"text": "no rule config"}}
			]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Level{
		"sql-injection": LevelError,
		"todo-comment":  LevelNote,
		"unknown-rule":  LevelWarning, // rule not found → default
	}
	if len(got.Results) != len(want) {
		t.Fatalf("results = %d, want %d", len(got.Results), len(want))
	}
	for _, r := range got.Results {
		if r.Level != want[r.RuleID] {
			t.Errorf("%s level = %q, want %q", r.RuleID, r.Level, want[r.RuleID])
		}
	}
}

// An explicit result-level "level" wins over the rule's defaultConfiguration.
func TestFromSARIFResultLevelOverridesRule(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "t",
				"rules": [{"id": "r", "defaultConfiguration": {"level": "note"}}]
			}},
			"results": [{"ruleId": "r", "level": "error", "message": {"text": "x"}}]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 1 || got.Results[0].Level != LevelError {
		t.Fatalf("result level should override rule default, got %+v", got.Results)
	}
}

// A result the tool marks as suppressed (e.g. Semgrep's in-source `nosem`) is not an active
// finding and must be dropped during parsing.
func TestFromSARIFSkipsSuppressed(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "semgrep"}},
			"results": [
				{"ruleId": "kept", "level": "error", "message": {"text": "real"}},
				{"ruleId": "hidden", "level": "error", "message": {"text": "nosem"},
				 "suppressions": [{"kind": "inSource"}]}
			]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 1 {
		t.Fatalf("results = %d, want 1 (suppressed dropped)", len(got.Results))
	}
	if got.Results[0].RuleID != "kept" {
		t.Errorf("kept the wrong result: %q", got.Results[0].RuleID)
	}
}

// Trivy-style SARIF: the numeric score lives in the rule's properties as a
// "security-severity" string, keyed to results by ruleId. A result-level property overrides.
func TestFromSARIFParsesSecuritySeverity(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "trivy",
				"rules": [{"id": "CVE-1", "properties": {"security-severity": "7.5"}}]
			}},
			"results": [
				{"ruleId": "CVE-1", "level": "warning", "message": {"text": "from rule"}},
				{"ruleId": "CVE-1", "level": "warning", "message": {"text": "result override"},
				 "properties": {"security-severity": "9.3"}},
				{"ruleId": "no-score", "level": "warning", "message": {"text": "none"}}
			]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	byMsg := map[string]Result{}
	for _, r := range got.Results {
		byMsg[r.Message] = r
	}
	if r := byMsg["from rule"]; !r.HasScore || r.Score != 7.5 {
		t.Errorf("rule-inherited score = %v (has=%v), want 7.5", r.Score, r.HasScore)
	}
	if r := byMsg["result override"]; !r.HasScore || r.Score != 9.3 {
		t.Errorf("result override score = %v, want 9.3", r.Score)
	}
	if r := byMsg["none"]; r.HasScore {
		t.Errorf("finding with no score should have HasScore=false, got %v", r.Score)
	}
	// The scored finding normalizes to critical despite a "warning" level.
	if s := byMsg["result override"].Severity(""); s != SeverityCritical {
		t.Errorf("severity = %q, want critical", s)
	}
}

func TestSARIFScoreRoundTrips(t *testing.T) {
	orig := Report{Results: []Result{
		{Tool: "trivy", RuleID: "CVE-1", Level: LevelWarning, Message: "x", Score: 7.5, HasScore: true},
	}}
	data, err := orig.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 1 || !got.Results[0].HasScore || got.Results[0].Score != 7.5 {
		t.Fatalf("score did not round-trip: %+v", got.Results)
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

func TestMarshalSARIFSingleDraugrTool(t *testing.T) {
	r := Report{Results: []Result{
		{Tool: "trivy", RuleID: "CVE-1", Level: LevelError, Message: "m1", Location: Location{URI: "go.mod"}},
		{Tool: "semgrep", RuleID: "go.xss", Level: LevelWarning, Message: "m2", Location: Location{URI: "h.go", StartLine: 3}},
	}}
	data, err := r.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Name string } `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID     string                `json:"ruleId"`
				Properties struct{ Tool string } `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	// One consolidated "Draugr" tool holding every finding.
	if len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "Draugr" {
		t.Fatalf("want a single Draugr run, got %d runs", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 2 {
		t.Fatalf("want 2 results in the run, got %d", len(log.Runs[0].Results))
	}
	// Originating scanner preserved per-finding.
	got := map[string]string{}
	for _, res := range log.Runs[0].Results {
		got[res.RuleID] = res.Properties.Tool
	}
	if got["CVE-1"] != "trivy" || got["go.xss"] != "semgrep" {
		t.Errorf("per-finding tool not preserved: %v", got)
	}

	// Round-trip: reading Draugr's own SARIF restores each result's originating tool.
	back, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	rt := map[string]string{}
	for _, res := range back.Results {
		rt[res.RuleID] = res.Tool
	}
	if rt["CVE-1"] != "trivy" || rt["go.xss"] != "semgrep" {
		t.Errorf("round-trip lost the originating tool: %v", rt)
	}
}
