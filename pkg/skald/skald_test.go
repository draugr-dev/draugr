package skald

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

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

func TestSortFindingsTieBreakers(t *testing.T) {
	// RuleIDs encode the expected final order (0..4) so the assertion is unambiguous.
	fs := []findingReport{
		{RuleID: "4", Priority: "P2", Level: "warning", Score: 5}, // P2, score 5, lowest level → last
		{RuleID: "0", Priority: "P1", Level: "note", Score: 1},    // highest priority → first
		{RuleID: "1", Priority: "P2", Level: "error", Score: 9},   // P2, highest score
		{RuleID: "3", Priority: "P2", Level: "error", Score: 5},   // score tie with "2", ruleID "3" > "2"
		{RuleID: "2", Priority: "P2", Level: "error", Score: 5},   // score tie, ruleID "2" first
	}
	sortFindings(fs)
	for i, f := range fs {
		if f.RuleID != string(rune('0'+i)) {
			got := make([]string, len(fs))
			for j, x := range fs {
				got[j] = x.RuleID
			}
			t.Fatalf("sort order = %v, want 0..4", got)
		}
	}
}

func TestSummarizePrioritiesCountsP4(t *testing.T) {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Control: "images", Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "x", Level: sarif.LevelNote, Priority: "P4"},
		}}},
	}}
	counts, _ := summarizePriorities(run, "")
	if counts == nil || counts.P4 != 1 {
		t.Fatalf("P4 count = %+v", counts)
	}
}

func TestWriteSARIFWriteError(t *testing.T) {
	if err := WriteSARIF(errWriter{}, prioritizedRun()); err == nil {
		t.Error("expected a write error to propagate")
	}
}

func TestRenderJSONWriteError(t *testing.T) {
	err := RenderJSON(errWriter{}, saga.Release{Version: "1"}, prioritizedRun(), sampleVerdict(), "")
	if err == nil {
		t.Error("expected a write error to propagate")
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

func TestRenderJSONStats(t *testing.T) {
	run := sampleRun()
	run.Stats = engine.Stats{Jobs: 12, Scans: 9, CacheHits: 2, Deduped: 1, Concurrency: 4}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "app", Version: "1.0"}, run, sampleVerdict(), ""); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Stats map[string]int `json:"stats"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for k, want := range map[string]int{"jobs": 12, "scans": 9, "cacheHits": 2, "deduped": 1, "concurrency": 4} {
		if doc.Stats[k] != want {
			t.Errorf("stats.%s = %d, want %d", k, doc.Stats[k], want)
		}
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
