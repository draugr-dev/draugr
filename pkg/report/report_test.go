package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
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
	for _, want := range []string{"Draugr — FAIL", "app 1.0", "Priorities:", "P1 1", "Fix first:", "CVE-1", "critical", "1 high"} {
		if !strings.Contains(s, want) {
			t.Errorf("console output missing %q\n%s", want, s)
		}
	}
	// The fix-first table carries a header (so newcomers can read it) and a Scanner column
	// naming the tool that flagged each finding.
	for _, want := range []string{"Scanner", "Control", "Location", "trivy", "gitleaks"} {
		if !strings.Contains(s, want) {
			t.Errorf("console fix-first table missing %q\n%s", want, s)
		}
	}
	// The header must precede the first finding row.
	if strings.Index(s, "Scanner") > strings.Index(s, "CVE-1") {
		t.Error("table header should be printed before the finding rows")
	}
	// Most-urgent (P1) should sort before the P3.
	if strings.Index(s, "CVE-1") > strings.Index(s, "CVE-2") {
		t.Error("P1 finding should be listed before the P3 finding")
	}
}

func TestConsoleSeverityBandsNoColorOnBuffer(t *testing.T) {
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	// Human report speaks severity bands, not SARIF levels.
	for _, band := range []string{"critical", "high", "medium"} {
		if !strings.Contains(s, band) {
			t.Errorf("expected severity band %q in output:\n%s", band, s)
		}
	}
	for _, level := range []string{"error", "warning", "note"} {
		if strings.Contains(s, level) {
			t.Errorf("human report should not show SARIF level %q:\n%s", level, s)
		}
	}
	// Writing to a plain buffer (not a TTY) must not emit ANSI escapes.
	if strings.Contains(s, "\x1b[") {
		t.Errorf("expected no ANSI color on a non-TTY writer:\n%q", s)
	}
}

func TestColorizer(t *testing.T) {
	off := colorizer{on: false}
	if got := off.paint(cCritical, "x"); got != "x" {
		t.Errorf("disabled colorizer changed text: %q", got)
	}
	on := colorizer{on: true}
	if got := on.paint(cCritical, "x"); got != "\x1b[1;31mx\x1b[0m" {
		t.Errorf("enabled colorizer = %q", got)
	}
	if got := on.paint("", "x"); got != "x" {
		t.Errorf("empty code should not wrap: %q", got)
	}
	// NO_COLOR disables even for a would-be terminal path.
	t.Setenv("NO_COLOR", "1")
	if newColorizer(os.Stdout).on {
		t.Error("NO_COLOR must disable color")
	}
}

func TestMarkdownRender(t *testing.T) {
	var b bytes.Buffer
	if err := (markdownReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"## Draugr — ❌ FAIL", "| Priority |", "| Scanner |", "### Controls", "### Fix first", "`CVE-1`"} {
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
	for _, want := range []string{"<!doctype html>", "Draugr —", "FAIL", "app 1.0", "CVE-1", "gitleaks", "<th>Scanner</th>", "</html>"} {
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

func TestConsoleTopN(t *testing.T) {
	results := make([]sarif.Result, 0, 15)
	for i := 0; i < 15; i++ {
		results = append(results, sarif.Result{RuleID: "R", Level: sarif.LevelWarning, Tool: "t"})
	}
	base := Data{
		Release: saga.Release{Name: "app"},
		Run:     engine.Result{Controls: map[string]plugin.ControlResult{"images": {Report: sarif.Report{Results: results}}}},
		Verdict: norn.Result{Verdict: norn.Pass},
	}
	render := func(topN int) string {
		d := base
		d.TopN = topN
		var b bytes.Buffer
		if err := (consoleReporter{}).Render(&b, d); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	// TopN 5 → 5 shown, "and 10 more".
	if s := render(5); !strings.Contains(s, "and 10 more") {
		t.Errorf("--top 5 of 15 should show 10 more:\n%s", s)
	}
	// TopN -1 (all) → no truncation tail.
	if s := render(-1); strings.Contains(s, "more finding(s)") {
		t.Errorf("--top 0/all should not truncate:\n%s", s)
	}
	// TopN larger than the finding count → no truncation tail.
	if s := render(50); strings.Contains(s, "more finding(s)") {
		t.Errorf("--top above the count should not truncate:\n%s", s)
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

// --min-priority used to filter only the JSON report, so the default console output silently
// ignored it. Every human format must honour it now.
func minPriorityData(band string) Data {
	results := []sarif.Result{
		{RuleID: "CVE-P1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy"},
		{RuleID: "CVE-P2", Level: sarif.LevelError, Priority: "P2", Tool: "trivy"},
		{RuleID: "CVE-P3", Level: sarif.LevelWarning, Priority: "P3", Tool: "trivy"},
		{RuleID: "CVE-P4", Level: sarif.LevelNote, Priority: "P4", Tool: "trivy"},
	}
	return Data{
		Release:     saga.Release{Name: "app"},
		Run:         engine.Result{Controls: map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: results}}}},
		Verdict:     norn.Result{Verdict: norn.Fail},
		MinPriority: band,
	}
}

func TestMinPriorityFiltersEveryHumanFormat(t *testing.T) {
	for _, format := range []string{"console", "markdown", "html", "junit"} {
		t.Run(format, func(t *testing.T) {
			r, err := For(format)
			if err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			if err := r.Render(&b, minPriorityData("P2")); err != nil {
				t.Fatal(err)
			}
			out := b.String()
			for _, want := range []string{"CVE-P1", "CVE-P2"} {
				if !strings.Contains(out, want) {
					t.Errorf("%s: %s should be listed at --min-priority P2", format, want)
				}
			}
			for _, unwanted := range []string{"CVE-P3", "CVE-P4"} {
				if strings.Contains(out, unwanted) {
					t.Errorf("%s: %s is below P2 and should be filtered out", format, unwanted)
				}
			}
		})
	}
}

// The counts describe the whole run even when the listing is filtered — otherwise you lose sight
// of the backlog you chose not to look at. The output has to say so.
func TestMinPriorityKeepsCountsAndExplainsItself(t *testing.T) {
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, minPriorityData("P2")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "P3 1") || !strings.Contains(out, "P4 1") {
		t.Errorf("priority counts should still describe the whole run:\n%s", out)
	}
	if !strings.Contains(out, "P2 and above") || !strings.Contains(out, "hidden") {
		t.Errorf("the filtered listing should say what it filtered:\n%s", out)
	}
}

func TestAtOrAbove(t *testing.T) {
	cases := []struct {
		got, want string
		expect    bool
	}{
		{"P1", "P2", true}, {"P2", "P2", true}, {"P3", "P2", false},
		{"p1", "p2", true}, // case-insensitive, like the CLI flag
		{"", "P2", false},  // unprioritized findings have no band to compare
	}
	for _, c := range cases {
		if got := atOrAbove(c.got, c.want); got != c.expect {
			t.Errorf("atOrAbove(%q,%q) = %v, want %v", c.got, c.want, got, c.expect)
		}
	}
}
