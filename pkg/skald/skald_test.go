package skald

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

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
			{Control: "images", Verdict: norn.Fail, Highest: sarif.SeverityHigh, Threshold: sarif.SeverityHigh,
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

// The run's timings are what answer "why was that slow", and CI keeps this document rather than
// the console the numbers were also printed to. A report that carries the job count and not the
// time it took describes the shape of the run and not its cost.
func TestRenderJSONReportsWhereTheTimeWent(t *testing.T) {
	run := sampleRun()
	run.Stats = engine.Stats{
		Jobs:        3,
		Scans:       3,
		Concurrency: 2,
		Duration:    90 * time.Second,
		ByControl: map[string]time.Duration{
			"sca":  61*time.Second + 200*time.Millisecond,
			"sast": 4 * time.Second,
		},
		ToolWaits: map[string]time.Duration{"trivy": 51 * time.Second},
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "app", Version: "1.0"}, run, sampleVerdict(), ""); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Stats struct {
			DurationMs  int64            `json:"durationMs"`
			ByControlMs map[string]int64 `json:"byControlMs"`
			ToolWaitsMs map[string]int64 `json:"toolWaitsMs"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc.Stats.DurationMs != 90_000 {
		t.Errorf("durationMs = %d, want 90000", doc.Stats.DurationMs)
	}
	if got := doc.Stats.ByControlMs["sca"]; got != 61_200 {
		t.Errorf("byControlMs[sca] = %d, want 61200", got)
	}
	if got := doc.Stats.ByControlMs["sast"]; got != 4_000 {
		t.Errorf("byControlMs[sast] = %d, want 4000", got)
	}
	// The wait is the figure the sum alone cannot explain: it is time inside those jobs that was
	// queueing rather than scanning, so a reader comparing them can tell a slow tool from a
	// contended one.
	if got := doc.Stats.ToolWaitsMs["trivy"]; got != 51_000 {
		t.Errorf("toolWaitsMs[trivy] = %d, want 51000", got)
	}
}

// A control faster than a millisecond is measured, not missing. Truncating it to 0 puts a
// "took no time" in a map whose every other entry is a real figure, and the entry that reads as
// a bug is the one nobody trusts the rest of the map after seeing.
func TestASubMillisecondControlIsRoundedRatherThanZeroed(t *testing.T) {
	run := sampleRun()
	run.Stats = engine.Stats{
		Jobs:      1,
		Scans:     1,
		Duration:  600 * time.Microsecond,
		ByControl: map[string]time.Duration{"secrets": 600 * time.Microsecond},
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "app", Version: "1.0"}, run, sampleVerdict(), ""); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Stats struct {
			DurationMs  int64            `json:"durationMs"`
			ByControlMs map[string]int64 `json:"byControlMs"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc.Stats.DurationMs != 1 {
		t.Errorf("durationMs = %d, want 1", doc.Stats.DurationMs)
	}
	if got := doc.Stats.ByControlMs["secrets"]; got != 1 {
		t.Errorf("byControlMs[secrets] = %d, want 1", got)
	}
}

// Unmeasured is not the same as instant. `cacheHits: 0` is a measurement and belongs in the
// document; a `durationMs: 0` beside it would be a claim no run can honestly make, and a
// consumer charting it has no way to tell the two zeroes apart.
func TestUnrecordedTimingsAreAbsentRatherThanZero(t *testing.T) {
	run := sampleRun()
	run.Stats = engine.Stats{Jobs: 2, Scans: 2, Concurrency: 2}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "app", Version: "1.0"}, run, sampleVerdict(), ""); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"durationMs", "byControlMs", "toolWaitsMs"} {
		if strings.Contains(buf.String(), key) {
			t.Errorf("%s present with nothing recorded:\n%s", key, buf.String())
		}
	}
	// The counts that *are* measurements stay, so this is an omission of the unknown rather than
	// of everything falsy.
	if !strings.Contains(buf.String(), `"cacheHits": 0`) {
		t.Errorf("cacheHits dropped along with the timings:\n%s", buf.String())
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

func TestScopeProvenanceAndBack(t *testing.T) {
	// The two halves have to agree, because one writes what the other reads: a scope written in
	// a shape the reader does not recognize is a scoped report that looks unscoped, which is the
	// failure the stamp exists to prevent.
	for _, tc := range []struct {
		name  string
		scope engine.Scope
		want  string
	}{
		{"components only", engine.Scope{Components: []string{"app", "api"}}, "components=app,api"},
		{"controls only", engine.Scope{Controls: []string{"sca"}}, "controls=sca"},
		{"both", engine.Scope{Components: []string{"app"}, Controls: []string{"sca", "secrets"}},
			"components=app controls=sca,secrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prov, ok := ScopeProvenance(tc.scope)
			if !ok {
				t.Fatal("a non-empty scope has something to say")
			}
			got, scoped := ScopeOfReport(sarif.Report{Provenance: []sarif.Provenance{prov}})
			if !scoped || got != tc.want {
				t.Errorf("got %q (scoped=%v), want %q", got, scoped, tc.want)
			}
		})
	}
}

func TestScopeProvenanceSaysNothingForAnUnscopedRun(t *testing.T) {
	// Nearly every run. Stamping an empty scope would make the marker meaningless — every
	// report would carry one, and a consumer could no longer tell by its presence.
	if _, ok := ScopeProvenance(engine.Scope{}); ok {
		t.Error("an unscoped run stamps nothing")
	}
	if got, scoped := ScopeOfReport(sarif.Report{}); scoped || got != "" {
		t.Errorf("a report with no stamp is unscoped, got %q (scoped=%v)", got, scoped)
	}
}

func TestScopeOfReportIgnoresOtherToolsProvenance(t *testing.T) {
	// Scanners write provenance too — a benchmark, a coverage figure. Reading one of those as a
	// scope would make an ordinary report look partial.
	rep := sarif.Report{Provenance: []sarif.Provenance{
		{Tool: "kube-bench", Fields: []sarif.Field{{Key: "benchmark", Value: "cis-1.9"}}},
	}}
	if got, scoped := ScopeOfReport(rep); scoped {
		t.Errorf("another tool's provenance is not a scope: %q", got)
	}
}

func TestMergedSARIFStampsAScopedRun(t *testing.T) {
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{
			"sca": {Report: sarif.Report{Results: []sarif.Result{{RuleID: "R"}}}},
		},
		Scope: engine.Scope{Components: []string{"app"}},
	}
	if got, scoped := ScopeOfReport(MergedSARIF(run)); !scoped || got != "components=app" {
		t.Errorf("the merged report should carry the scope, got %q (scoped=%v)", got, scoped)
	}

	run.Scope = engine.Scope{}
	if _, scoped := ScopeOfReport(MergedSARIF(run)); scoped {
		t.Error("an unscoped run's SARIF must be exactly what it always was")
	}
}

func TestJSONReportCarriesTheScope(t *testing.T) {
	var b bytes.Buffer
	run := engine.Result{Scope: engine.Scope{
		Components: []string{"app"}, SkippedComponents: []string{"frontend"},
	}}
	if err := RenderJSON(&b, saga.Release{Name: "r", Version: "1"}, run, norn.Result{Verdict: norn.Pass}, ""); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Scope *struct {
			Components        []string `json:"components"`
			SkippedComponents []string `json:"skippedComponents"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Scope == nil {
		t.Fatalf("a scoped run's report must say so:\n%s", b.String())
	}
	if len(doc.Scope.Components) != 1 || doc.Scope.Components[0] != "app" {
		t.Errorf("components: %+v", doc.Scope)
	}
	if len(doc.Scope.SkippedComponents) != 1 || doc.Scope.SkippedComponents[0] != "frontend" {
		t.Errorf("skipped: %+v", doc.Scope)
	}

	// And an unscoped run has no such field, so the presence of one is what carries the meaning.
	b.Reset()
	if err := RenderJSON(&b, saga.Release{Name: "r", Version: "1"}, engine.Result{}, norn.Result{Verdict: norn.Pass}, ""); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), `"scope"`) {
		t.Errorf("an unscoped report should carry no scope field:\n%s", b.String())
	}
}

// A control that could not run has to be in the document.
//
// It is the case that produced no findings and therefore no verdict outcome, so listing outcomes
// dropped it: a consumer counting controls saw a shorter list rather than a failure, and every
// remaining field described what was found rather than what was attempted. Reading this document
// is exactly the situation where nobody is watching the terminal that says otherwise.
func TestJSONNamesAControlThatCouldNotRun(t *testing.T) {
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{
			"sca": {Report: sarif.Report{Results: []sarif.Result{
				{RuleID: "R", Level: sarif.LevelError, Message: "m"},
			}}},
		},
		ScanErrors: map[string][]string{
			"dast": {`nuclei: executable file not found in $PATH`},
			"sca":  {"trivy-fs: exit status 2"},
		},
	}
	verdict := norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
		{Control: "sca", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1}},
	}}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "app", Version: "1"}, run, verdict, ""); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var doc struct {
		Controls []struct {
			Name       string   `json:"name"`
			Verdict    string   `json:"verdict"`
			ScanErrors []string `json:"scanErrors"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}

	byName := map[string]int{}
	for i, c := range doc.Controls {
		byName[c.Name] = i
	}
	// dast produced nothing at all, which is exactly why it used to be absent.
	i, ok := byName["dast"]
	if !ok {
		t.Fatalf("the control that produced nothing is missing:\n%s", buf.String())
	}
	if doc.Controls[i].Verdict != "fail" {
		t.Errorf("a control that never ran is not a pass: %+v", doc.Controls[i])
	}
	if len(doc.Controls[i].ScanErrors) != 1 ||
		!strings.Contains(doc.Controls[i].ScanErrors[0], "not found") {
		t.Errorf("the reason it did not run is missing: %+v", doc.Controls[i])
	}
	// And one that ran, found things, and still hit an error carries the error too: its counts
	// describe what the scanners that did run found, which is not the same as what is there.
	j := byName["sca"]
	if len(doc.Controls[j].ScanErrors) == 0 {
		t.Errorf("a control with findings and an error is still partial: %+v", doc.Controls[j])
	}
}

// A clean run carries none of it, or every consumer learns to ignore the fields that matter.
func TestJSONOmitsTheCaveatsWhenThereAreNone(t *testing.T) {
	var buf bytes.Buffer
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{}},
	}}
	verdict := norn.Result{Verdict: norn.Pass, Controls: []norn.ControlOutcome{
		{Control: "sca", Verdict: norn.Pass},
	}}
	if err := RenderJSON(&buf, saga.Release{Name: "app", Version: "1"}, run, verdict, ""); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	for _, absent := range []string{"scanErrors", "notMeasured"} {
		if strings.Contains(buf.String(), absent) {
			t.Errorf("a complete run must not carry %q:\n%s", absent, buf.String())
		}
	}
}

// The skip travels too, naming what could not be answered and for which component.
func TestJSONCarriesWhatWasNotMeasured(t *testing.T) {
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{"infrastructure": {Report: sarif.Report{}}},
		Skipped: []engine.SkippedJob{{
			Control: "infrastructure", Scanner: "kube-bench-job", Component: "team-a",
			Reason: "audits the whole cluster and cannot be narrowed to namespace team-a",
		}},
	}
	verdict := norn.Result{Verdict: norn.Pass, Controls: []norn.ControlOutcome{
		{Control: "infrastructure", Verdict: norn.Pass},
	}}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, saga.Release{Name: "app", Version: "1"}, run, verdict, ""); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var doc struct {
		Controls []struct {
			ScanErrors []string `json:"scanErrors"`
		} `json:"controls"`
		NotMeasured []struct {
			Control, Scanner, Component, Reason string
		} `json:"notMeasured"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.NotMeasured) != 1 {
		t.Fatalf("expected one entry, got %+v", doc.NotMeasured)
	}
	if doc.NotMeasured[0].Component != "team-a" || doc.NotMeasured[0].Scanner != "kube-bench-job" {
		t.Errorf("wrong entry: %+v", doc.NotMeasured[0])
	}
	// A skip is not a failure: nothing went wrong, and the scanner was never going to be able to
	// answer. Recording it as a scan error would make every namespace-scoped cluster look broken.
	for _, c := range doc.Controls {
		if len(c.ScanErrors) > 0 {
			t.Errorf("a skip is not an error: %+v", c)
		}
	}
}

// A narrowed report says so, and a reader can get the band back out.
//
// The round trip is the point. A file that is a subset and does not declare it is
// indistinguishable from a complete one — and `draugr diff`, reading it as the base, would report
// every finding below the band as fixed.
func TestMinPriorityProvenanceRoundTrips(t *testing.T) {
	prov, ok := MinPriorityProvenance("P2")
	if !ok {
		t.Fatal("a declared band produced no provenance")
	}
	rep := sarif.Report{Provenance: []sarif.Provenance{prov}}
	band, narrowed := MinPriorityOfReport(rep)
	if !narrowed || band != "P2" {
		t.Errorf("read back %q/%v, want P2/true", band, narrowed)
	}

	// A complete report declares nothing, so it stays byte-identical to what it has always been.
	if _, ok := MinPriorityProvenance(""); ok {
		t.Error("an unnarrowed report must not stamp a band")
	}
	if band, narrowed := MinPriorityOfReport(sarif.Report{}); narrowed || band != "" {
		t.Errorf("a report with no provenance read as narrowed to %q", band)
	}
}

func TestEveryMergedFindingSaysWhichControlFoundIt(t *testing.T) {
	// The merged document is all a downstream consumer gets, and a run holds its reports keyed by
	// control rather than stamped with it. Two controls reporting one rule id are two separate
	// things to do; without the control on the finding, anything grouping by rule id makes them
	// one and reports half the work.
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "SHARED-1", Tool: "trivy", Message: "from the dependency scan"},
		}}},
		"sast": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "SHARED-1", Tool: "semgrep", Message: "from the code scan"},
		}}},
	}}

	got := map[string]string{}
	for _, res := range MergedSARIF(run).Results {
		got[res.Message] = res.Control
	}
	want := map[string]string{
		"from the dependency scan": "sca",
		"from the code scan":       "sast",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("controls = %v, want %v", got, want)
	}
}

func TestAControlSurvivesTheFile(t *testing.T) {
	// A report is written and read back — by `draugr diff`, by a platform, by anything consuming
	// the artifact. A field that only exists in memory is one every one of those does without.
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"secrets": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "gitleaks.aws-key", Tool: "gitleaks", Message: "a key"},
		}}},
	}}

	encoded, err := MergedSARIF(run).MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	back, err := sarif.FromSARIF(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != 1 || back.Results[0].Control != "secrets" {
		t.Errorf("read back %+v, want the control preserved", back.Results)
	}
}

func TestMergedSARIFCarriesWhatTheRunConsulted(t *testing.T) {
	// The evidence a pipeline uploads is the SARIF, not report.json, so anything explaining a
	// band to somebody downstream has to find it here.
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{
			"sca": {Report: sarif.Report{Results: []sarif.Result{{RuleID: "CVE-2021-44228"}}}},
		},
		Consulted: []sarif.Consulted{
			{Signal: "kev", AsOf: "2026-08-01", Entries: 1100},
			{Signal: "epss", AsOf: "2026-08-02", Entries: 280000, Threshold: 0.5},
		},
	}
	got := MergedSARIF(run).Consulted
	if len(got) != 2 || got[0].Signal != "kev" || got[1].Threshold != 0.5 {
		t.Errorf("merged consulted = %+v, want both feeds with the EPSS threshold", got)
	}

	// And a run that enriched nothing says nothing, rather than an empty block that reads like
	// a feed with no entries.
	run.Consulted = nil
	if got := MergedSARIF(run).Consulted; len(got) != 0 {
		t.Errorf("a run with no exploitability data reported %+v", got)
	}
}
