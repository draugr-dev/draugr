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

// Every advertised format resolves, and answers to the name it is advertised under.
//
// Driven by Formats() rather than by a list written out here, because both are true of a registry
// whose newest entry is registered under one name and reports another — and Formats() is what the
// --report help, the unknown-format error and the artifact filenames are all built from, so it is
// the list that has to work.
func TestForAndFormats(t *testing.T) {
	got := Formats()
	if len(got) == 0 {
		t.Fatal("Formats() is empty")
	}
	if !slices.IsSorted(got) {
		t.Errorf("Formats() = %v, want sorted", got)
	}
	for _, f := range got {
		r, err := For(f)
		if err != nil {
			t.Errorf("advertised format %q does not resolve: %v", f, err)
			continue
		}
		if r.Format() != f {
			t.Errorf("format %q is registered under a name it does not answer to: %q", f, r.Format())
		}
		// A format missing from formatMeta still writes a file, under a fallback name and with no
		// content type — so a publisher delivers it as something a consumer cannot identify.
		if _, ok := formatMeta[f]; !ok {
			t.Errorf("format %q has no entry in formatMeta, so it has no filename or content type", f)
		}
	}
	if _, err := For("nope"); err == nil {
		t.Error("expected error for unknown format")
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

// Color behavior now lives in pkg/tui and is tested there; this only asserts the report uses
// it — a non-TTY writer must never receive escape codes.
func TestConsoleUsesSharedPalette(t *testing.T) {
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b[") {
		t.Errorf("a buffer is not a terminal; no color expected:\n%q", b.String())
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

// A filter honored by one format and ignored by the others is a flag that does nothing where
// the reader is most likely to be looking. Every human format has to honor it.
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

// A control that couldn't run must appear in the report. Dropping it makes the output get
// shorter exactly when something has gone wrong, which is the one time a reader is counting on
// it to get longer.
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

// An explanation belongs under the control it explains.
//
// Indentation is the only thing that says whose failure a message is, and the message names a
// scanner rather than a control — so one printed after the table sits against whichever control
// happens to be listed last and reads as that one's problem, with nothing in the sentence to
// contradict it. The control that errored is deliberately not the last one here, because that is
// the only arrangement where the two placements differ.
func TestConsoleAttachesAFailureToItsOwnControl(t *testing.T) {
	d := Data{
		Run: engine.Result{
			Controls: map[string]plugin.ControlResult{
				"infrastructure": {Report: sarif.Report{
					Results: []sarif.Result{{RuleID: "R", Level: sarif.LevelWarning, Message: "m"}},
				}},
				"secrets": {Report: sarif.Report{
					Results: []sarif.Result{{RuleID: "S", Level: sarif.LevelError, Message: "m"}},
				}},
			},
			ScanErrors: map[string][]string{"infrastructure": {"kube-bench-job always audits the whole cluster"}},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "infrastructure", Verdict: norn.Fail, Counts: sarif.Counts{Warning: 1}},
			{Control: "secrets", Verdict: norn.Fail, Counts: sarif.Counts{Error: 1}},
		}},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	infra := strings.Index(out, "infrastructure")
	msg := strings.Index(out, "kube-bench-job")
	secrets := strings.Index(out, "secrets")
	if infra < 0 || msg < 0 || secrets < 0 {
		t.Fatalf("expected both controls and the message:\n%s", out)
	}
	if infra > msg || msg > secrets {
		t.Errorf("the failure must sit between its own control and the next one, not after the table:\n%s", out)
	}
}

// A flag silently ignored by one format is byte-identical output with and without it. SARIF is
// the worst place for that: the machine consumer with the strongest reason to ask for "just the
// P1s" is also the one least able to notice it did not get them.
func TestSARIFHonorsMinPriority(t *testing.T) {
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
		name      string
		feeds     []FeedProvenance
		escalated int
		want      string
	}{
		{"none", nil, 0, ""},
		{
			// Dates alone say the feeds were consulted, not what they did. Without the effect the
			// only way to find out is to read every finding and then doubt yourself.
			"consulted and changed nothing",
			[]FeedProvenance{{Name: "kev", FetchedAt: fetched}}, 0,
			"Exploitability: KEV 2026-08-01 — nothing raised",
		},
		{
			"one finding raised",
			[]FeedProvenance{{Name: "kev", FetchedAt: fetched}}, 1,
			"Exploitability: KEV 2026-08-01 — 1 finding raised",
		},
		{
			"several raised",
			[]FeedProvenance{{Name: "kev", FetchedAt: fetched}}, 4,
			"Exploitability: KEV 2026-08-01 — 4 findings raised",
		},
		{
			// A file the operator supplied has no fetch date, and saying so is more accurate
			// than inventing today's.
			"a supplied file",
			[]FeedProvenance{{Name: "kev"}}, 0,
			"Exploitability: KEV (file) — nothing raised",
		},
		{
			"stale is said out loud",
			[]FeedProvenance{{Name: "epss", FetchedAt: fetched, Stale: true}}, 0,
			"Exploitability: EPSS 2026-08-01, stale — nothing raised",
		},
		{
			"both",
			[]FeedProvenance{{Name: "kev", FetchedAt: fetched}, {Name: "epss", FetchedAt: fetched}}, 2,
			"Exploitability: KEV 2026-08-01 · EPSS 2026-08-01 — 2 findings raised",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exploitabilityLine(c.feeds, c.escalated); got != c.want {
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

func TestToolBuildLines(t *testing.T) {
	// pinned and signed share a line — "Draugr fetched these and checked them" is one fact, and a
	// reader who wants the distinction has the JSON. Anything weaker gets its own, because that
	// is the one they have to decide about.
	got := toolBuildLines([]ToolBuild{
		{Name: "trivy", Version: "0.69.3", Level: "signed"},
		{Name: "gitleaks", Version: "8.30.1", Level: "pinned"},
	})
	if len(got) != 1 || !strings.Contains(got[0], "gitleaks 8.30.1, trivy 0.69.3") {
		t.Errorf("verified tools not grouped: %q", got)
	}

	// A tool Draugr installed but could not verify is not the same as one it never touched, and
	// both are called out.
	got = toolBuildLines([]ToolBuild{
		{Name: "trivy", Version: "0.69.3", Level: "pinned"},
		{Name: "nuclei", Version: "3.5.0", Level: "unverified",
			Reason: "installed by Draugr, nothing published to verify it against"},
		{Name: "semgrep", Version: "1.99.0", Level: "external",
			Reason: "found on PATH; Draugr did not install it"},
	})
	if len(got) != 3 {
		t.Fatalf("expected each weaker level on its own line: %q", got)
	}
	if !strings.Contains(got[1], "nothing published") {
		t.Errorf("an unverified install reads as if Draugr never fetched it: %q", got[1])
	}
	if !strings.Contains(got[2], "did not install it") {
		t.Errorf("the reason is what makes it actionable: %q", got[2])
	}

	if toolBuildLines(nil) != nil {
		t.Error("a run with no external scanners should say nothing")
	}
}

func TestToolBuildsAbsentFromAnUnenrichedReport(t *testing.T) {
	// A native-only scan uses no external tool, and a "Scanners:" line listing nothing would be
	// noise on every such run.
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, goldenCleanData()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Scanners:") {
		t.Errorf("a run with no external tools mentioned them:\n%s", buf.String())
	}
}

func TestJUnitCarriesTheAdvisoryLink(t *testing.T) {
	// A test panel shows the failure body when someone opens a finding, and "CVE-2020-14343" with
	// no link is a number they have to retype into a search engine. The one thing they are about
	// to go looking for is where to read more, so it travels with the finding.
	var b bytes.Buffer
	d := goldenCleanData()
	d.Run = engine.Result{Controls: map[string]plugin.ControlResult{"sca": {Report: sarif.Report{
		Tool: "trivy",
		Rules: map[string]sarif.Rule{
			"CVE-2020-14343": {HelpURI: "https://avd.aquasec.com/nvd/cve-2020-14343"},
		},
		Results: []sarif.Result{
			{Tool: "Trivy", RuleID: "CVE-2020-14343", Level: sarif.LevelError,
				Message:  "PyYAML: incomplete fix for CVE-2020-1747",
				Location: sarif.Location{URI: "app/requirements.txt", StartLine: 3}},
			// No rule metadata and no recognizable scheme: nowhere honest to point.
			{Tool: "Trivy", RuleID: "house-style-42", Level: sarif.LevelWarning,
				Message: "something local"},
		},
	}}}}
	d.Verdict = norn.Result{Verdict: norn.Fail,
		Controls: []norn.ControlOutcome{{Control: "sca", Verdict: norn.Fail}}}

	if err := (junitReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	var suites junitTestsuites
	if err := xml.Unmarshal(b.Bytes(), &suites); err != nil {
		t.Fatal(err)
	}
	bodies := map[string]string{}
	for _, s := range suites.Suites {
		for _, tc := range s.TestCases {
			if tc.Failure != nil {
				bodies[tc.Name] = tc.Failure.Body
			}
		}
	}
	var cve, local string
	for name, body := range bodies {
		if strings.HasPrefix(name, "CVE-2020-14343") {
			cve = body
		}
		if strings.HasPrefix(name, "house-style-42") {
			local = body
		}
	}
	if !strings.Contains(cve, "https://avd.aquasec.com/nvd/cve-2020-14343") {
		t.Errorf("no advisory link in the failure body: %q", cve)
	}
	if !strings.Contains(cve, "incomplete fix") {
		t.Errorf("the link replaced the description instead of joining it: %q", cve)
	}
	// A wrong link is worse than none, so a rule with nowhere to point gets no trailing blank
	// lines pretending there was somewhere.
	if local != "something local" {
		t.Errorf("a finding with no advisory should carry only its message, got %q", local)
	}
}

func TestRepositoriesFromDeduplicatesAcrossControls(t *testing.T) {
	// Every repository scanner checks out independently, so five controls over one repository
	// record the same repository five times. That is one fact about one checkout, and reporting
	// it five times is how a useful line becomes wallpaper.
	repo := func(url, rev string) sarif.Report {
		return sarif.Report{Provenance: []sarif.Provenance{{Tool: "t", Fields: []sarif.Field{
			{Key: "repository", Value: url}, {Key: "revision", Value: rev},
		}}}}
	}
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca":     {Report: repo(".", "abc123def456")},
		"secrets": {Report: repo(".", "abc123def456")},
		"sast":    {Report: repo(".", "abc123def456")},
	}}
	got := RepositoriesFrom(run)
	if len(got) != 1 {
		t.Fatalf("expected one line for one checkout, got %d: %+v", len(got), got)
	}
	if got[0].Short() != "abc123de" {
		t.Errorf("Short() = %q", got[0].Short())
	}
}

func TestRepositoriesFromKeepsControlsThatDisagree(t *testing.T) {
	// Independent checkouts mean a branch that moves mid-scan can genuinely be read at two
	// commits. Collapsing that would be an assumption presented as evidence — and the report
	// would name a revision that half of it did not describe.
	repo := func(rev string) sarif.Report {
		return sarif.Report{Provenance: []sarif.Provenance{{Tool: "t", Fields: []sarif.Field{
			{Key: "repository", Value: "."}, {Key: "revision", Value: rev},
		}}}}
	}
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca":     {Report: repo("aaaaaaaa1111")},
		"secrets": {Report: repo("bbbbbbbb2222")},
	}}
	if got := RepositoriesFrom(run); len(got) != 2 {
		t.Errorf("two controls read two commits; report showed %d: %+v", len(got), got)
	}
}

func TestRepositoriesFromIgnoresProvenanceAboutSomethingElse(t *testing.T) {
	// kube-bench records a benchmark, not a repository. It belongs in the per-control block.
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"kubernetes": {Report: sarif.Report{Provenance: []sarif.Provenance{{
			Tool: "kube-bench", Fields: []sarif.Field{{Key: "benchmark", Value: "cis-1.8"}},
		}}}},
	}}
	if got := RepositoriesFrom(run); len(got) != 0 {
		t.Errorf("non-repository provenance leaked into the repository line: %+v", got)
	}
}

func TestRepositoryLinesReadAsAClauseNotAnAlarm(t *testing.T) {
	got := repositoryLines([]RepositoryProvenance{{URL: ".", Revision: "abc123def456"}})
	if len(got) != 1 || got[0] != "Scanned: . at abc123de" {
		t.Errorf("got %q", got)
	}
	got = repositoryLines([]RepositoryProvenance{{URL: ".", Revision: "abc123def456", Uncommitted: 7}})
	if len(got) != 1 || got[0] != "Scanned: . at abc123de (7 uncommitted files not included)" {
		t.Errorf("got %q", got)
	}
	// One file is one file. A report that says "1 uncommitted files" was written by a program.
	got = repositoryLines([]RepositoryProvenance{{URL: ".", Revision: "abc123def456", Uncommitted: 1}})
	if !strings.Contains(got[0], "1 uncommitted file ") {
		t.Errorf("got %q", got)
	}
	if repositoryLines(nil) != nil {
		t.Error("a run that read no repository should say nothing")
	}
}

func TestPerControlProvenanceDropsTheRepositoryFields(t *testing.T) {
	// The repository is reported once for the run. Leaving it in the per-control block too would
	// print the same checkout under every control, in a section headed "measured against".
	d := goldenCleanData()
	d.Run = engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{Provenance: []sarif.Provenance{{
			Tool: "trivy-fs", Fields: []sarif.Field{
				{Key: "repository", Value: "."}, {Key: "revision", Value: "abc123"},
			},
		}}}},
	}}
	if lines := provenanceLines(d); len(lines) != 0 {
		t.Errorf("repository provenance appeared per control: %+v", lines)
	}
}

func TestRepositoryLineSaysWhenTheTreeIsNotReproducible(t *testing.T) {
	// The committed line and the working-tree line describe opposite situations with the same
	// number: one counts what is missing, the other counts what is uniquely there.
	working := repositoryLines([]RepositoryProvenance{{
		URL: ".", Revision: "abc123def456", Uncommitted: 2, WorkingTree: true,
	}})
	if len(working) != 1 || working[0] != "Scanned: . working tree at abc123de+ (2 uncommitted files, not reproducible)" {
		t.Errorf("got %q", working)
	}
	committed := repositoryLines([]RepositoryProvenance{{
		URL: ".", Revision: "abc123def456", Uncommitted: 2,
	}})
	if committed[0] != "Scanned: . at abc123de (2 uncommitted files not included)" {
		t.Errorf("got %q", committed)
	}
	// A clean working tree is the same bytes as its commit, so no "+" and nothing to warn about.
	clean := repositoryLines([]RepositoryProvenance{{
		URL: ".", Revision: "abc123def456", WorkingTree: true,
	}})
	if clean[0] != "Scanned: . working tree at abc123de" {
		t.Errorf("got %q", clean)
	}
}

// scopedData is a two-component run where only one was scanned.
func scopedData() Data {
	d := goldenCleanData()
	d.Components = []ComponentVerdict{{Name: "app", Verdict: norn.Pass}}
	d.Scope = &Scope{Components: []string{"app"}, SkippedComponents: []string{"frontend", "payments"}}
	return d
}

func TestConsoleQualifiesAScopedVerdict(t *testing.T) {
	// A reader who takes one line from this report takes the verdict line, so a PASS covering a
	// third of the release must not be readable on its own.
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, scopedData()); err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(b.String(), "\n")
	if !strings.Contains(head, "1 of 3 components") {
		t.Errorf("the verdict line should say what it covered:\n%s", head)
	}
}

func TestConsoleNamesComponentsThatWereNotScanned(t *testing.T) {
	// A component absent from the breakdown renders identically to one that passed, and absence
	// is exactly how a reader concludes there was nothing to find.
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, scopedData()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"frontend", "payments"} {
		if !strings.Contains(b.String(), name) {
			t.Errorf("%q should be listed:\n%s", name, b.String())
		}
	}
	if got := strings.Count(b.String(), "not scanned"); got != 2 {
		t.Errorf("both skipped components should say why, got %d:\n%s", got, b.String())
	}
	// And neither may read as a pass.
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.Contains(line, "frontend") && strings.Contains(line, "pass") {
			t.Errorf("a component nobody scanned must not read as passing: %q", line)
		}
	}
}

func TestConsoleUnscopedOutputIsUnchanged(t *testing.T) {
	// Nearly every report is unscoped, and none of them should have moved.
	var scoped, plain bytes.Buffer
	d := goldenCleanData()
	if err := (consoleReporter{}).Render(&plain, d); err != nil {
		t.Fatal(err)
	}
	d.Scope = nil
	if err := (consoleReporter{}).Render(&scoped, d); err != nil {
		t.Fatal(err)
	}
	if plain.String() != scoped.String() {
		t.Error("a nil scope must render exactly as before")
	}
	if strings.Contains(plain.String(), "scope:") || strings.Contains(plain.String(), "not scanned") {
		t.Errorf("an unscoped run should say nothing about scope:\n%s", plain.String())
	}
}

// A history finding's location is a path in a commit, and a reader who takes it for a current one
// draws the opposite conclusion from the right facts: the path does not exist, so the finding
// looks like something already dealt with. A credential reachable from any commit is still
// fetchable by anyone who can clone.
func TestConsoleSaysWhenAFindingComesFromHistory(t *testing.T) {
	d := Data{
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"secrets": {Control: "secrets", Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
				{
					RuleID: "github-pat", Level: sarif.LevelError, Message: "secret in a commit",
					Location:   sarif.Location{URI: "old/scripts/check.ps1", StartLine: 1},
					Historical: true,
				},
			}}},
		}},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "git history") {
		t.Errorf("a history finding must say so:\n%s", out)
	}
	if !strings.Contains(out, "Rotate it") {
		t.Errorf("removing a secret from the tip is not remediation; the report should say so:\n%s", out)
	}
}

// And a tree finding must not claim it, or the marker means nothing.
func TestConsoleSaysNothingAboutHistoryForATreeFinding(t *testing.T) {
	d := Data{
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"secrets": {Control: "secrets", Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
				{
					RuleID: "github-pat", Level: sarif.LevelError, Message: "secret in the tree",
					Location: sarif.Location{URI: "new/scripts/check.ps1", StartLine: 1},
				},
			}}},
		}},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "git history") {
		t.Errorf("a tree finding claimed to be historical:\n%s", buf.String())
	}
}

// A scanner that was planned and then not run has to appear in the report.
//
// It is the case that looks exactly like success: the control has findings from the scanners that
// could run, the component reads pass, and nothing anywhere says a question went unanswered. The
// note is the only thing standing between that and a PASS which means less than it appears to.
func TestConsoleNamesAScannerThatCouldNotAnswer(t *testing.T) {
	d := Data{
		Run: engine.Result{
			Controls: map[string]plugin.ControlResult{
				"infrastructure": {Report: sarif.Report{
					Results: []sarif.Result{{RuleID: "R", Level: sarif.LevelWarning, Message: "m"}},
				}},
			},
			Skipped: []engine.SkippedJob{{
				Control:   "infrastructure",
				Scanner:   "kube-bench-job",
				Component: "team-a",
				Reason:    "audits the whole cluster and cannot be narrowed to namespace team-a",
			}},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "infrastructure", Verdict: norn.Fail, Counts: sarif.Counts{Warning: 1}},
		}},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	// The scanner, the component it did not answer for, and why — an entry naming only the
	// scanner leaves a reader unable to tell whether it mattered.
	for _, want := range []string{"Not measured:", "kube-bench-job", "team-a", "cannot be narrowed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// And a run where nothing was skipped says nothing, or the block becomes something readers learn
// to scroll past — which takes the run that did skip something down with it.
func TestConsoleSaysNothingWhenEveryScannerCouldAnswer(t *testing.T) {
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, Data{
		Run:     engine.Result{Controls: map[string]plugin.ControlResult{}},
		Verdict: norn.Result{Verdict: norn.Pass},
	}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(buf.String(), "Not measured") {
		t.Errorf("a complete run must not carry an empty caveat:\n%s", buf.String())
	}
}

// The markdown report is what gets pasted into a pull request, which is where somebody decides
// whether a green check means anything. A skip missing there is missing at the moment it counts.
func TestMarkdownNamesAScannerThatCouldNotAnswer(t *testing.T) {
	d := Data{
		Run: engine.Result{
			Controls: map[string]plugin.ControlResult{
				"infrastructure": {Report: sarif.Report{
					Results: []sarif.Result{{RuleID: "R", Level: sarif.LevelWarning, Message: "m"}},
				}},
			},
			Skipped: []engine.SkippedJob{{
				Control: "infrastructure", Scanner: "kube-bench-job", Component: "team-a",
				Reason: "audits the whole cluster and cannot be narrowed to namespace team-a",
			}},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "infrastructure", Verdict: norn.Fail, Counts: sarif.Counts{Warning: 1}},
		}},
	}
	var buf bytes.Buffer
	if err := (markdownReporter{}).Render(&buf, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"Not measured", "kube-bench-job", "team-a", "cannot be narrowed"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q:\n%s", want, buf.String())
		}
	}
}
