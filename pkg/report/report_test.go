package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
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
	for _, f := range []string{"console", "markdown", "html", "junit", "json", "sarif"} {
		r, err := For(f)
		if err != nil || r.Format() != f {
			t.Errorf("For(%q) = %v, %v", f, r, err)
		}
	}
	if _, err := For("nope"); err == nil {
		t.Error("expected error for unknown format")
	}
	if got := Formats(); len(got) != 6 {
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

func TestHTMLRender(t *testing.T) {
	var b bytes.Buffer
	if err := (htmlReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"<!doctype html>", "Draugr —", "FAIL", "app 1.0", "CVE-1", "gitleaks", "</html>"} {
		if !strings.Contains(s, want) {
			t.Errorf("html output missing %q", want)
		}
	}
	// P1 finding sorts before the P3.
	if strings.Index(s, "CVE-1") > strings.Index(s, "CVE-2") {
		t.Error("P1 finding should render before the P3 finding")
	}
}

func TestHTMLEscapesFindingContent(t *testing.T) {
	d := Data{
		Release: saga.Release{Name: "app"},
		Run: engine.Result{Controls: map[string]plugin.ControlResult{"images": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "R", Level: sarif.LevelError, Tool: "t", Message: "<script>alert(1)</script>"},
		}}}}},
		Verdict: norn.Result{Verdict: norn.Fail},
	}
	var b bytes.Buffer
	if err := (htmlReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<script>alert(1)</script>") {
		t.Error("html reporter must escape finding content")
	}
	if !strings.Contains(b.String(), "&lt;script&gt;") {
		t.Error("expected escaped finding content")
	}
}

func TestJUnitRender(t *testing.T) {
	var b bytes.Buffer
	if err := (junitReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	// Must be well-formed XML.
	var suites junitTestsuites
	if err := xml.Unmarshal(b.Bytes(), &suites); err != nil {
		t.Fatalf("junit output not valid XML: %v", err)
	}
	if suites.Name != "draugr" {
		t.Errorf("root name = %q", suites.Name)
	}
	// sampleData has 3 findings across images(2) + secrets(1).
	if suites.Tests != 3 || suites.Failures != 3 {
		t.Errorf("tests=%d failures=%d, want 3/3", suites.Tests, suites.Failures)
	}
	if len(suites.Suites) != 2 {
		t.Fatalf("want one suite per control, got %d", len(suites.Suites))
	}
}

func TestJUnitCleanControlPasses(t *testing.T) {
	d := Data{
		Release: saga.Release{Name: "app"},
		Run:     engine.Result{Controls: map[string]plugin.ControlResult{"images": {Report: sarif.Report{}}}},
		Verdict: norn.Result{Verdict: norn.Pass, Controls: []norn.ControlOutcome{{Control: "images", Verdict: norn.Pass}}},
	}
	var b bytes.Buffer
	if err := (junitReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	var suites junitTestsuites
	if err := xml.Unmarshal(b.Bytes(), &suites); err != nil {
		t.Fatal(err)
	}
	if suites.Failures != 0 || suites.Tests != 1 {
		t.Errorf("clean control: tests=%d failures=%d, want 1/0", suites.Tests, suites.Failures)
	}
	if len(suites.Suites) != 1 || suites.Suites[0].TestCases[0].Failure != nil {
		t.Error("clean control should emit one passing testcase")
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
