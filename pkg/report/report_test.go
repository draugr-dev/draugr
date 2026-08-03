package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
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
	// "by priority" rather than "Fix first:": the heading now says whether the table is a
	// shortlist or the whole set, and this fixture is small enough to be the whole set.
	for _, want := range []string{"Draugr — FAIL", "app 1.0", "Priorities:", "P1 1", "by priority", "CVE-1", "critical", "1 high"} {
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

// Colour behaviour now lives in pkg/tui and is tested there; this only asserts the report uses
// it — a non-TTY writer must never receive escape codes.
func TestConsoleUsesSharedPalette(t *testing.T) {
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b[") {
		t.Errorf("a buffer is not a terminal; no colour expected:\n%q", b.String())
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
	for _, want := range []string{"<!doctype html>", "Draugr —", "FAIL", "app 1.0", "CVE-1", "gitleaks", ">Scanner</th>", "</html>"} {
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

// A rule id names a finding without explaining it — "DS-0002" is meaningless to the reader we
// care about most. The message belongs in the table.
func TestConsoleShowsTheFindingMessage(t *testing.T) {
	d := Data{
		Release: saga.Release{Name: "app"},
		Run: engine.Result{Controls: map[string]plugin.ControlResult{"iac": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "DS-0002", Level: sarif.LevelError, Priority: "P1", Tool: "trivy-config",
				Message: "Default Seccomp profile not set — the container runs unconfined"},
		}}}}},
		Verdict: norn.Result{Verdict: norn.Fail},
	}
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "Default Seccomp profile not set") {
		t.Errorf("the finding's message should appear under its row:\n%s", out)
	}
	// The id is still there — it's what you search upstream with.
	if !strings.Contains(out, "DS-0002") {
		t.Errorf("the rule id should still be shown:\n%s", out)
	}
}

func TestFindingSummary(t *testing.T) {
	if got := findingSummary("  a\nb   c  "); got != "a b c" {
		t.Errorf("newlines and runs of spaces should collapse, got %q", got)
	}
	if got := findingSummary(""); got != "" {
		t.Errorf("an empty message should render nothing, got %q", got)
	}
	long := strings.Repeat("x", messageWidth+40)
	got := findingSummary(long)
	if len([]rune(got)) > messageWidth {
		t.Errorf("summary should stay within %d chars, got %d", messageWidth, len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a truncated summary should say so: %q", got)
	}
}

// The console links a rule id to wherever the scanner said the rule is documented — which is
// how an id like "DS-0002", with no public advisory to derive a URL from, becomes reachable.
func TestConsoleLinksTheScannerPublishedHelpURI(t *testing.T) {
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Report: sarif.Report{
			Results: []sarif.Result{{RuleID: "DS-0002", Level: sarif.LevelError, Message: "root user"}},
			Rules:   map[string]sarif.Rule{"DS-0002": {HelpURI: "https://avd.aquasec.com/misconfig/ds002"}},
		}},
	}}}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Not a terminal, so the link degrades to plain text: the id must still be there, intact.
	if !strings.Contains(buf.String(), "DS-0002") {
		t.Errorf("rule id missing:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "avd.aquasec.com") {
		t.Errorf("url should not be written as visible text off a terminal:\n%s", buf.String())
	}
}

// A long namespaced rule id must not push the columns after it off the screen.
func TestShortRuleID(t *testing.T) {
	short := "CVE-2021-36159"
	if got := shortRuleID(short); got != short {
		t.Errorf("shortRuleID(%q) = %q, want it untouched", short, got)
	}
	long := "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag"
	got := shortRuleID(long)
	if len([]rune(got)) > ruleIDWidth {
		t.Errorf("len(%q) = %d, want at most %d", got, len([]rune(got)), ruleIDWidth)
	}
	// The tail is the specific half — that's what has to survive.
	if !strings.HasSuffix(got, "github-actions-mutable-action-tag") {
		t.Errorf("got %q, want the tail of the id kept", got)
	}
	if !strings.HasPrefix(got, "…") {
		t.Errorf("got %q, want it marked as shortened", got)
	}
	// The whole point: cut on a separator, not mid-word. "…ction-tag.github-…" reads as
	// corruption; a whole segment reads as truncation.
	if got != "…github-actions-mutable-action-tag" {
		t.Errorf("got %q, want the cut on a dot boundary", got)
	}
}

func TestShortRuleIDFallsBackWhenNoSeparatorFits(t *testing.T) {
	// A single long unsegmented id has no dot to cut on. Trimming by width is then the only
	// option, and is still better than pushing every later column off the screen.
	long := strings.Repeat("x", 80)
	got := shortRuleID(long)
	if len([]rune(got)) != ruleIDWidth {
		t.Errorf("len(%q) = %d, want exactly %d", got, len([]rune(got)), ruleIDWidth)
	}
	if !strings.HasPrefix(got, "…") {
		t.Errorf("got %q, want it marked as shortened", got)
	}
}

func TestShortRuleIDKeepsAWholeSegmentEvenWhenTwoWouldNotFit(t *testing.T) {
	// The dot search runs inside the visible tail, so a boundary just past the cut is used
	// rather than one before it — otherwise the result would exceed the column.
	got := shortRuleID("a.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccccc")
	if len([]rune(got)) > ruleIDWidth {
		t.Errorf("len(%q) = %d, want at most %d", got, len([]rune(got)), ruleIDWidth)
	}
	if strings.Contains(strings.TrimPrefix(got, "…"), "b") {
		t.Errorf("got %q, want a clean segment boundary", got)
	}
}

// Shortening is for the table only: the machine formats keep the id whole, because that's what
// you feed back to the scanner or search upstream with.
func TestLongRuleIDStaysWholeInJSON(t *testing.T) {
	long := "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag"
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Report: sarif.Report{Results: []sarif.Result{{RuleID: long, Level: sarif.LevelError}}}},
	}}}
	var console, machine bytes.Buffer
	if err := (consoleReporter{}).Render(&console, d); err != nil {
		t.Fatalf("console: %v", err)
	}
	if strings.Contains(console.String(), long) {
		t.Errorf("console should shorten the id:\n%s", console.String())
	}
	if err := (sarifReporter{}).Render(&machine, d); err != nil {
		t.Fatalf("sarif: %v", err)
	}
	if !strings.Contains(machine.String(), long) {
		t.Errorf("sarif must keep the whole id:\n%s", machine.String())
	}
}

// Compact reaches the machine formats and leaves the human ones alone — making those harder to
// read would be the opposite of the point.
func TestCompactAffectsOnlyTheMachineFormats(t *testing.T) {
	base := sampleData()
	compact := sampleData()
	compact.Compact = true

	for _, format := range []string{"json", "sarif"} {
		var full, lean bytes.Buffer
		if err := reporters[format].Render(&full, base); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if err := reporters[format].Render(&lean, compact); err != nil {
			t.Fatalf("%s compact: %v", format, err)
		}
		if lean.Len() >= full.Len() {
			t.Errorf("%s: compact (%d) not smaller than full (%d)", format, lean.Len(), full.Len())
		}
		if !json.Valid(lean.Bytes()) {
			t.Errorf("%s: compact output is not valid JSON", format)
		}
	}
	for _, format := range []string{"console", "markdown"} {
		var full, lean bytes.Buffer
		if err := reporters[format].Render(&full, base); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if err := reporters[format].Render(&lean, compact); err != nil {
			t.Fatalf("%s compact: %v", format, err)
		}
		if full.String() != lean.String() {
			t.Errorf("%s should ignore --compact", format)
		}
	}
}

// A control that couldn't run must appear in the report. It used to vanish, so the output got
// shorter exactly when something had gone wrong.
func TestConsoleNamesControlsThatCouldNotRun(t *testing.T) {
	d := Data{
		Run: engine.Result{
			Controls:   map[string]plugin.ControlResult{},
			ScanErrors: map[string][]string{"sca": {`trivy-fs: exec: "trivy": executable file not found`}},
		},
		Verdict: norn.Result{Verdict: norn.Fail},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Controls:", "sca", "ERROR", "did not run", "executable file not found"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// The reassuring line is the whole problem: it must not appear when a control didn't run.
	if strings.Contains(out, "No findings. ✓") {
		t.Errorf("a scan that didn't run must not report a clean tick:\n%s", out)
	}
}

// A control that produced findings *and* errored is partial, not merely failing.
func TestConsoleMarksPartialControlsAsError(t *testing.T) {
	d := Data{
		Run: engine.Result{
			Controls: map[string]plugin.ControlResult{"sast": {Report: sarif.Report{
				Results: []sarif.Result{{RuleID: "R", Level: sarif.LevelError, Message: "m"}},
			}}},
			ScanErrors: map[string][]string{"sast": {"gosec: exit status 2"}},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "sast", Verdict: norn.Fail},
		}},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "ERROR") {
		t.Errorf("a control with findings and an error should read ERROR, not FAIL:\n%s", buf.String())
	}
}

// --min-priority used to be silently ignored by --format sarif: byte-identical output with and
// without the flag. The machine consumer with the strongest reason to ask for "just the P1s" was
// the one it didn't serve, and the one least able to notice.
func TestSARIFHonoursMinPriority(t *testing.T) {
	d := minPriorityData("P2")
	var full, filtered bytes.Buffer
	if err := (sarifReporter{}).Render(&full, Data{Release: d.Release, Run: d.Run, Verdict: d.Verdict}); err != nil {
		t.Fatal(err)
	}
	if err := (sarifReporter{}).Render(&filtered, d); err != nil {
		t.Fatal(err)
	}
	if full.Len() == filtered.Len() {
		t.Fatalf("filtered SARIF is the same size as unfiltered (%d bytes) — the flag did nothing", full.Len())
	}
	out := filtered.String()
	for _, want := range []string{"CVE-P1", "CVE-P2"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s is at or above P2 and should be in the SARIF", want)
		}
	}
	for _, unwanted := range []string{"CVE-P3", "CVE-P4"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("%s is below P2 and should have been filtered out", unwanted)
		}
	}
}

// A finding with no priority was never ranked — prioritization did not run for it. Dropping it
// would read an unset field as "low", which is the worst available interpretation.
func TestSARIFKeepsUnprioritizedFindings(t *testing.T) {
	d := minPriorityData("P1")
	d.Run.Controls["sca"] = plugin.ControlResult{Report: sarif.Report{Results: []sarif.Result{
		{RuleID: "NO-PRIORITY", Level: sarif.LevelWarning, Tool: "trivy"},
	}}}
	var b bytes.Buffer
	if err := (sarifReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "NO-PRIORITY") {
		t.Errorf("an unprioritized finding should survive --min-priority:\n%s", b.String())
	}
}

// Filtering must not mutate the run: the same Data renders in several formats and then goes to
// publishers, so a destructive filter would silently truncate everything rendered after it.
func TestSARIFFilterLeavesTheRunIntact(t *testing.T) {
	d := minPriorityData("P1")
	before := len(d.Run.Controls["sca"].Report.Results)
	var b bytes.Buffer
	if err := (sarifReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if after := len(d.Run.Controls["sca"].Report.Results); after != before {
		t.Errorf("rendering filtered SARIF mutated the run: %d results before, %d after", before, after)
	}
}

// erroredRunData is a run where one control reported findings and another could not run at all.
// The second is the dangerous case: with no verdict entry, a reporter that only walks
// Verdict.Controls omits it, and the report describes a thinner run rather than a broken one.
func erroredRunData() Data {
	return Data{
		Release: saga.Release{Name: "app", Version: "1.0"},
		Run: engine.Result{
			Controls: map[string]plugin.ControlResult{
				"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
					{RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy"},
				}}},
			},
			ScanErrors: map[string][]string{"dast": {"nuclei: executable file not found in $PATH"}},
			Suppressed: 3,
			SBOMs:      []sbom.Document{{Format: "spdx-json"}},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "sca", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1}},
		}},
	}
}

// A control whose scanner never ran found nothing because it looked at nothing. Every format a
// person reads has to say so — this held for the console and for neither other format, and a
// shared HTML or markdown report is the one most likely to be handed to someone else as a
// record of what was checked.
func TestEveryHumanFormatReportsAControlThatCouldNotRun(t *testing.T) {
	for _, format := range []string{"console", "markdown", "html"} {
		t.Run(format, func(t *testing.T) {
			r, err := For(format)
			if err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			if err := r.Render(&b, erroredRunData()); err != nil {
				t.Fatal(err)
			}
			out := b.String()
			if !strings.Contains(out, "dast") {
				t.Errorf("%s: the control that failed is missing entirely:\n%s", format, out)
			}
			if !strings.Contains(out, "ERROR") {
				t.Errorf("%s: nothing marks the run as incomplete:\n%s", format, out)
			}
			if !strings.Contains(out, "nuclei") {
				t.Errorf("%s: the reason the control failed is not reported:\n%s", format, out)
			}
		})
	}
}

// An excluded finding that leaves no trace reads exactly like one that was never made, which is
// what suppress-rather-than-delete exists to prevent.
func TestEveryHumanFormatReportsSuppressions(t *testing.T) {
	for _, format := range []string{"console", "markdown", "html"} {
		t.Run(format, func(t *testing.T) {
			r, _ := For(format)
			var b bytes.Buffer
			if err := r.Render(&b, erroredRunData()); err != nil {
				t.Fatal(err)
			}
			if out := b.String(); !strings.Contains(out, "3 findings suppressed") &&
				!strings.Contains(out, "3 finding(s) suppressed") {
				t.Errorf("%s: the suppression count is not reported:\n%s", format, out)
			}
		})
	}
}

// Filtering the listing without saying so leaves the counts and the table openly contradicting
// each other, and the reader to notice.
func TestEveryHumanFormatSaysItFiltered(t *testing.T) {
	for _, format := range []string{"console", "markdown", "html"} {
		t.Run(format, func(t *testing.T) {
			r, _ := For(format)
			var b bytes.Buffer
			if err := r.Render(&b, minPriorityData("P2")); err != nil {
				t.Fatal(err)
			}
			out := b.String()
			if !strings.Contains(out, "P2 and above") {
				t.Errorf("%s: does not say the listing was filtered:\n%s", format, out)
			}
			if !strings.Contains(out, "hidden") && !strings.Contains(out, "not listed") {
				t.Errorf("%s: does not say how many were left out:\n%s", format, out)
			}
		})
	}
}

// What a run did to its targets belongs where the verdict is read. A scan that probed a live
// endpoint is a thing that happened, and the report is where someone looks to find out what
// happened — not only the docs describing the control.
func TestConsoleReportsWhatTheRunDid(t *testing.T) {
	d := sampleData()
	d.Run.Effects = []plugin.Effect{{
		Kind:   plugin.EffectNetwork,
		Detail: "sends probe traffic to the endpoint",
	}}
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"network", "sends probe traffic to the endpoint"} {
		if !strings.Contains(out, want) {
			t.Errorf("console should report %q:\n%s", want, out)
		}
	}
}

// A read-only run says nothing, so the line means something when it appears.
func TestConsoleSaysNothingWhenTheRunOnlyRead(t *testing.T) {
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "network") {
		t.Errorf("a read-only run should not mention effects:\n%s", b.String())
	}
}

// A finding answers "what is wrong". Evidence also has to answer "what was measured, and against
// what" — and for a compliance control that is the question asked first.
func TestProvenanceLines(t *testing.T) {
	t.Parallel()

	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"infrastructure": {Report: sarif.Report{Provenance: []sarif.Provenance{
			{Tool: "kube-bench-job", Version: "0.15.6", Fields: []sarif.Field{{Key: "benchmark", Value: "gke-1.9.0"}}},
			{Tool: "draugr-k8s-policies", Fields: []sarif.Field{{Key: "coverage", Value: "20 of 34"}}},
		}}},
		"sca": {Report: sarif.Report{Provenance: []sarif.Provenance{{Tool: "trivy", Version: "0.69.3"}}}},
	}}}

	got := provenanceLines(d)
	if len(got) != 3 {
		t.Fatalf("want an entry per scanner account, got %d: %+v", len(got), got)
	}
	// Control order is deterministic, or two runs of the same scan render differently.
	if got[0].Control != "infrastructure" || got[2].Control != "sca" {
		t.Errorf("controls should be ordered, got %q then %q", got[0].Control, got[2].Control)
	}
	if got[0].Label() != "kube-bench-job 0.15.6" {
		t.Errorf("Label = %q", got[0].Label())
	}
	// A scanner that reported no version is named without one rather than as "unknown".
	if got[1].Label() != "draugr-k8s-policies" {
		t.Errorf("Label without a version = %q", got[1].Label())
	}
	// A version alone is still worth reporting: it answers "what produced this".
	if got[2].Detail != "" || got[2].Label() != "trivy 0.69.3" {
		t.Errorf("version-only entry = %+v", got[2])
	}
}

// Nothing to say means nothing rendered — not an empty heading on every report.
func TestProvenanceOmittedWhenThereIsNone(t *testing.T) {
	t.Parallel()

	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{}},
	}}}
	if got := provenanceLines(d); len(got) != 0 {
		t.Errorf("want nothing, got %+v", got)
	}

	var buf bytes.Buffer
	if err := (markdownReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Measured against") {
		t.Errorf("an empty section should not be rendered:\n%s", buf.String())
	}
}

func TestDedupeMessagesCollapsesIdenticalFailures(t *testing.T) {
	// Two components whose scanner binary is missing produce the same sentence twice. Two
	// identical lines invite the reader to look for the difference between them, and there is
	// none — the duplicate says nothing about which job it came from.
	got := dedupeMessages([]string{
		`run semgrep: exec: "semgrep": executable file not found in $PATH`,
		`run semgrep: exec: "semgrep": executable file not found in $PATH`,
		"trivy: connection refused",
	})
	want := []string{
		`run semgrep: exec: "semgrep": executable file not found in $PATH (2 jobs)`,
		"trivy: connection refused",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestDedupeMessagesKeepsDistinctFailuresAndOrder(t *testing.T) {
	// Different failures are different information, and first-seen order keeps the list stable
	// between runs.
	in := []string{"c failed", "a failed", "b failed", "a failed"}
	got := dedupeMessages(in)
	want := []string{"c failed", "a failed (2 jobs)", "b failed"}
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestDedupeMessagesOnNothing(t *testing.T) {
	if got := dedupeMessages(nil); len(got) != 0 {
		t.Errorf("got %q, want empty", got)
	}
}

func TestConsoleOmitsTheComponentBlockWhenThereIsNothingToTellApart(t *testing.T) {
	// One component repeats what the headline already said, and a block that always appears is
	// one nobody reads.
	var b bytes.Buffer
	d := goldenCleanData()
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Components:") {
		t.Errorf("no breakdown without components to compare:\n%s", b.String())
	}
}

func TestMarkdownRendersTheComponentTable(t *testing.T) {
	var b bytes.Buffer
	if err := (markdownReporter{}).Render(&b, goldenFullData()); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{
		"### Components",
		"| payments | **FAIL** | 3 | 2 | 1 | 0 | sca, secrets |",
		"| internal-tool | pass | 0 | 0 | 0 | 0 | - |",
		"2 findings not tied to a component",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// suppressedBy builds a report whose findings were set aside, some with a name against them.
func suppressedBy(names ...string) Data {
	var results []sarif.Result
	for i, n := range names {
		results = append(results, sarif.Result{
			RuleID: fmt.Sprintf("CVE-%d", i), Level: sarif.LevelError,
			Suppression: &sarif.Suppression{Kind: "external", Justification: "accepted", AcceptedBy: n},
		})
	}
	return Data{
		Run: engine.Result{
			Suppressed: len(names),
			Controls:   map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: results}}},
		},
	}
}

func TestSuppressionLineNamesWhoAccepted(t *testing.T) {
	// The name is the point of recording it. A count of unattributed says *that* there is a gap;
	// it does not say who to ask about the rest, which is the question an auditor arrives with.
	got := suppressionLine(suppressedBy("a.reviewer", "a.reviewer", "b.owner", ""))
	want := "4 findings suppressed by config.exclude — 2 accepted by a.reviewer, 1 accepted by b.owner, 1 unattributed"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestSuppressionLineWithNobodyNamed(t *testing.T) {
	got := suppressionLine(suppressedBy("", ""))
	want := "2 findings suppressed by config.exclude — 2 unattributed"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestSuppressionLineIsAbsentWithNothingSuppressed(t *testing.T) {
	if got := suppressionLine(Data{}); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestSuppressionLineOrdersAcceptorsStably(t *testing.T) {
	// Map iteration would reorder this between runs, and a report offered as evidence should
	// not differ from itself.
	first := suppressionLine(suppressedBy("z.last", "a.first"))
	for range 5 {
		if got := suppressionLine(suppressedBy("z.last", "a.first")); got != first {
			t.Fatalf("unstable order:\n%s\n%s", first, got)
		}
	}
	if !strings.Contains(first, "a.first, 1 accepted by z.last") {
		t.Errorf("expected alphabetical: %q", first)
	}
}

func TestExploitabilityLine(t *testing.T) {
	fetched := time.Date(2026, 8, 1, 9, 12, 0, 0, time.UTC)
	cases := []struct {
		name  string
		feeds []FeedProvenance
		want  string
	}{
		{"none", nil, ""},
		{
			"fetched",
			[]FeedProvenance{{Name: "kev", FetchedAt: fetched}},
			"Exploitability: KEV 2026-08-01",
		},
		{
			// A file the operator supplied has no fetch date, and saying so is more accurate
			// than inventing today's.
			"a supplied file",
			[]FeedProvenance{{Name: "kev"}},
			"Exploitability: KEV (file)",
		},
		{
			"stale is said out loud",
			[]FeedProvenance{{Name: "epss", FetchedAt: fetched, Stale: true}},
			"Exploitability: EPSS 2026-08-01, stale",
		},
		{
			"both",
			[]FeedProvenance{{Name: "kev", FetchedAt: fetched}, {Name: "epss", FetchedAt: fetched}},
			"Exploitability: KEV 2026-08-01 · EPSS 2026-08-01",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exploitabilityLine(c.feeds); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestEscalationNote(t *testing.T) {
	if got := escalationNote(nil); got != "" {
		t.Errorf("nothing raised it, so nothing should be claimed: %q", got)
	}
	// What it was ranked as, not what it was raised from: the Severity column still shows the
	// scanner's rating, so "raised from high" beside a row reading "high" would say nothing.
	got := escalationNote(&sarif.Escalation{
		From: sarif.SeverityHigh, To: sarif.SeverityCritical,
		Signal: "kev", Detail: "on KEV", AsOf: "2026-08-01",
	})
	if got != "↑ ranked as critical — on KEV (2026-08-01)" {
		t.Errorf("got %q", got)
	}
	// No date: the claim stands without one rather than being dropped or dated wrongly.
	got = escalationNote(&sarif.Escalation{From: sarif.SeverityLow, To: sarif.SeverityMedium, Detail: "EPSS 0.9"})
	if got != "↑ ranked as medium — EPSS 0.9" {
		t.Errorf("got %q", got)
	}
}

func TestExploitabilityAbsentWhenNoEnrichment(t *testing.T) {
	// The whole feature is invisible on a run that did not use it. A header with nothing under
	// it is a question the reader has to answer for themselves.
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, goldenCleanData()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Exploitability") {
		t.Errorf("unenriched run mentions exploitability:\n%s", buf.String())
	}

	buf.Reset()
	if err := (markdownReporter{}).Render(&buf, goldenCleanData()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Exploitability") {
		t.Errorf("markdown mentions it too:\n%s", buf.String())
	}
}

func TestExploitabilityInMarkdownAndHTML(t *testing.T) {
	d := goldenEnrichedData()

	var md bytes.Buffer
	if err := (markdownReporter{}).Render(&md, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Exploitability data", "`kev`", "fetched 2026-08-01", "**stale**"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown missing %q:\n%s", want, md.String())
		}
	}

	var html bytes.Buffer
	if err := (htmlReporter{}).Render(&html, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Exploitability data", "2026-08-01", "(stale)", "sha256:15b44d7c9c57"} {
		if !strings.Contains(html.String(), want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestExploitabilityInJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := (jsonReporter{}).Render(&buf, goldenEnrichedData()); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Exploitability []struct {
			Name      string `json:"name"`
			URL       string `json:"url"`
			FetchedAt string `json:"fetchedAt"`
			SHA256    string `json:"sha256"`
			Stale     bool   `json:"stale"`
		} `json:"exploitability"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Exploitability) != 2 {
		t.Fatalf("got %d feeds, want 2:\n%s", len(doc.Exploitability), buf.String())
	}
	kev := doc.Exploitability[0]
	if kev.Name != "kev" || kev.URL == "" || kev.SHA256 == "" || kev.FetchedAt == "" {
		t.Errorf("incomplete provenance: %+v", kev)
	}
	if !doc.Exploitability[1].Stale {
		t.Error("the stale feed is not marked stale in the JSON")
	}
}
