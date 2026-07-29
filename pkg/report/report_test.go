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
