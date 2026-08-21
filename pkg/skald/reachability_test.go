package skald

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func renderJSON(t *testing.T, run engine.Result, minPriority string) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "x", Version: "1"}, run, norn.Result{}, minPriority); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestReportJSONCountsAllThreeVerdicts(t *testing.T) {
	doc := renderJSON(t, engine.Result{Reachability: engine.ReachabilitySummary{
		Analyzer: "govulncheck", Reachable: 2, Unreachable: 6, Unknown: 3, Contributed: 1,
	}}, "")
	got, ok := doc["reachability"].(map[string]any)
	if !ok {
		t.Fatalf("no reachability block: %v", doc)
	}
	for key, want := range map[string]float64{"reachable": 2, "unreachable": 6, "unknown": 3, "contributed": 1} {
		if got[key] != want {
			t.Errorf("%s = %v, want %v", key, got[key], want)
		}
	}
	if got["analyzer"] != "govulncheck" {
		t.Errorf("analyzer = %v", got["analyzer"])
	}
}

func TestReportJSONOmitsReachabilityWhenNoneRan(t *testing.T) {
	if doc := renderJSON(t, engine.Result{}, ""); doc["reachability"] != nil {
		t.Errorf("reachability = %v, want absent when no analyzer ran", doc["reachability"])
	}
}

func TestReportJSONFindingCarriesTheCallPath(t *testing.T) {
	// The evidence a reachability claim is judged on has to reach whatever reads the file.
	run := engine.Result{
		Reachability: engine.ReachabilitySummary{Analyzer: "govulncheck", Reachable: 1},
		Controls: map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
			Tool: "trivy", Results: []sarif.Result{{
				RuleID: "CVE-2022-32149", Level: sarif.LevelError, Priority: "P1",
				Reachability: &sarif.Reachability{
					State: sarif.ReachabilityReachable, Analyzer: "govulncheck", Method: "call-graph",
					Paths: []sarif.CallPath{{Frames: []sarif.CallFrame{{Function: "main"}}}},
				},
			}},
		}}},
	}
	doc := renderJSON(t, run, "P4")
	findings, ok := doc["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings = %v", doc["findings"])
	}
	f := findings[0].(map[string]any)
	rc, ok := f["reachability"].(map[string]any)
	if !ok {
		t.Fatalf("finding carries no reachability: %v", f)
	}
	if rc["state"] != "reachable" || rc["paths"] == nil {
		t.Errorf("verdict or evidence missing: %v", rc)
	}
}
