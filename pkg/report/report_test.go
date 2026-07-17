package report

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

func sampleData() Data {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Score: 9.8, HasScore: true, Priority: "P1",
				Location: sarif.Location{URI: "alpine:1", StartLine: 0}, Tool: "trivy"},
			{RuleID: "CVE-2", Level: sarif.LevelWarning, Priority: "P3", Tool: "trivy"},
		}}},
		"secrets": {Control: "secrets", Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
			{RuleID: "aws-key", Level: sarif.LevelError, Priority: "P2", Tool: "gitleaks"},
		}}},
	}}
	verdict := norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
		{Control: "images", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1, Warning: 1}},
		{Control: "secrets", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1}},
	}}
	return Data{Release: saga.Release{Name: "app", Version: "1.0"}, Run: run, Verdict: verdict}
}

func TestForAndFormats(t *testing.T) {
	for _, f := range []string{"console", "markdown", "json", "sarif"} {
		r, err := For(f)
		if err != nil || r.Format() != f {
			t.Errorf("For(%q) = %v, %v", f, r, err)
		}
	}
	if _, err := For("nope"); err == nil {
		t.Error("expected error for unknown format")
	}
	if got := Formats(); len(got) != 4 {
		t.Errorf("Formats() = %v", got)
	}
}

func TestConsoleRender(t *testing.T) {
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"Draugr — FAIL", "app 1.0", "Priorities:", "P1 1", "Fix first:", "CVE-1", "trivy"} {
		if !strings.Contains(s, want) {
			t.Errorf("console output missing %q\n%s", want, s)
		}
	}
	// Most-urgent (P1) should sort before the P3.
	if strings.Index(s, "CVE-1") > strings.Index(s, "CVE-2") {
		t.Error("P1 finding should be listed before the P3 finding")
	}
}

func TestMarkdownRender(t *testing.T) {
	var b bytes.Buffer
	if err := (markdownReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"## Draugr — ❌ FAIL", "| Priority |", "### Controls", "### Fix first", "`CVE-1`"} {
		if !strings.Contains(s, want) {
			t.Errorf("markdown output missing %q\n%s", want, s)
		}
	}
}

func TestJSONReporterDelegates(t *testing.T) {
	var b bytes.Buffer
	if err := (jsonReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("json reporter output not valid JSON: %v", err)
	}
	if doc["verdict"] != "fail" {
		t.Errorf("verdict = %v", doc["verdict"])
	}
}

func TestSarifReporter(t *testing.T) {
	var b bytes.Buffer
	if err := (sarifReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	rep, err := sarif.FromSARIF(b.Bytes())
	if err != nil {
		t.Fatalf("sarif reporter output not valid SARIF: %v", err)
	}
	if len(rep.Results) == 0 {
		t.Error("expected merged results in SARIF")
	}
}

func TestConsoleTruncatesUnprioritized(t *testing.T) {
	// 15 unprioritized findings → no priority line, and the "…and N more" tail.
	results := make([]sarif.Result, 0, 15)
	for i := 0; i < 15; i++ {
		results = append(results, sarif.Result{RuleID: "R", Level: sarif.LevelWarning, Tool: "t"})
	}
	d := Data{
		Release: saga.Release{Name: "app"},
		Run:     engine.Result{Controls: map[string]plugin.ControlResult{"images": {Report: sarif.Report{Results: results}}}},
		Verdict: norn.Result{Verdict: norn.Pass},
	}
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if strings.Contains(s, "Priorities:") {
		t.Error("unprioritized run should not print a priorities line")
	}
	if !strings.Contains(s, "and 5 more") {
		t.Errorf("expected truncation of 15 → 10 shown + 5 more:\n%s", s)
	}
}

func TestConsoleNoFindings(t *testing.T) {
	d := Data{Release: saga.Release{Name: "app"}, Verdict: norn.Result{Verdict: norn.Pass}}
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No findings") || !strings.Contains(b.String(), "PASS") {
		t.Errorf("expected a clean PASS summary, got:\n%s", b.String())
	}
}
