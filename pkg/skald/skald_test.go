package skald

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func sampleRun() engine.Result {
	return engine.Result{
		Controls: map[string]plugin.ControlResult{
			"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
				{RuleID: "CVE-1", Level: sarif.LevelError, Location: sarif.Location{URI: "img"}},
			}}},
		},
		Stats: engine.Stats{Jobs: 1, Scans: 1},
	}
}

func sampleVerdict() norn.Result {
	return norn.Result{
		Verdict: norn.Fail,
		Controls: []norn.ControlOutcome{
			{Control: "images", Verdict: norn.Fail, Highest: sarif.LevelError, Threshold: sarif.LevelError,
				Counts: sarif.Counts{Error: 1}},
		},
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	err := RenderJSON(&buf, saga.Release{Name: "app", Version: "1.0"}, sampleRun(), sampleVerdict())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc["verdict"] != "fail" {
		t.Errorf("verdict = %v", doc["verdict"])
	}
	if !strings.Contains(buf.String(), "\"images\"") {
		t.Errorf("missing control name:\n%s", buf.String())
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleRun()); err != nil {
		t.Fatal(err)
	}
	got, err := sarif.FromSARIF(buf.Bytes())
	if err != nil {
		t.Fatalf("output not valid SARIF: %v", err)
	}
	if len(got.Results) != 1 {
		t.Fatalf("want 1 merged result, got %d", len(got.Results))
	}
}

func TestMergedSARIFOrders(t *testing.T) {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"b": {Report: sarif.Report{Results: []sarif.Result{{RuleID: "B", Location: sarif.Location{URI: "b"}}}}},
		"a": {Report: sarif.Report{Results: []sarif.Result{{RuleID: "A", Location: sarif.Location{URI: "a"}}}}},
	}}
	merged := MergedSARIF(run)
	if len(merged.Results) != 2 {
		t.Fatalf("want 2 results, got %d", len(merged.Results))
	}
}
