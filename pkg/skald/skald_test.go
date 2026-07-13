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

func prioritizedRun() engine.Result {
	return engine.Result{
		Controls: map[string]plugin.ControlResult{
			"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
				{RuleID: "CVE-1", Level: sarif.LevelError, Score: 9.1, HasScore: true, Priority: "P1", Location: sarif.Location{URI: "img", StartLine: 3}},
				{RuleID: "CVE-2", Level: sarif.LevelWarning, Priority: "P3"},
			}}},
			"secrets": {Control: "secrets", Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
				{RuleID: "aws-key", Level: sarif.LevelError, Priority: "P2"},
			}}},
		},
		Stats: engine.Stats{Jobs: 2, Scans: 2},
	}
}

func TestRenderJSONPriorityCounts(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "a", Version: "1"}, prioritizedRun(), sampleVerdict(), ""); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Priorities map[string]int   `json:"priorities"`
		Findings   []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Priorities["p1"] != 1 || doc.Priorities["p2"] != 1 || doc.Priorities["p3"] != 1 {
		t.Errorf("priority counts = %v", doc.Priorities)
	}
	if len(doc.Findings) != 0 {
		t.Errorf("no findings list expected without --min-priority, got %d", len(doc.Findings))
	}
}

func TestRenderJSONMinPriorityFilterAndOrder(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "a", Version: "1"}, prioritizedRun(), sampleVerdict(), "P2"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Priority, Control, RuleID, Location string
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	// P1 and P2 survive the P2 floor; P3 is filtered out.
	if len(doc.Findings) != 2 {
		t.Fatalf("want 2 findings (P1,P2), got %d: %+v", len(doc.Findings), doc.Findings)
	}
	if doc.Findings[0].Priority != "P1" || doc.Findings[1].Priority != "P2" {
		t.Errorf("findings not ordered most-urgent first: %+v", doc.Findings)
	}
	if doc.Findings[0].Control != "images" || doc.Findings[0].Location != "img:3" {
		t.Errorf("finding attribution wrong: %+v", doc.Findings[0])
	}
}

func TestRenderJSONNoPriorityWhenUnprioritized(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "a", Version: "1"}, sampleRun(), sampleVerdict(), "P1"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\"priorities\"") {
		t.Error("unprioritized run should omit priorities")
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
	err := RenderJSON(&buf, saga.Release{Name: "app", Version: "1.0"}, sampleRun(), sampleVerdict(), "")
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
