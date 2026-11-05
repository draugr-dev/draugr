package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// marksData holds the findings whose mark has to agree with the severity printed beside it, across
// two controls, two repositories and two components, so a mark collapsed across any of them cannot
// pass.
func marksData() Data {
	const repoA, repoB = "https://github.com/acme/a.git", "https://github.com/acme/b.git"
	floorReason := "a leaked credential is high priority wherever it is found"
	secrets := []sarif.Result{
		// Rated medium, held at high by the control's severity floor, on a component already at C1.
		{RuleID: "floored-key", Level: sarif.LevelWarning, Priority: "P1", SeverityFloor: sarif.SeverityHigh,
			Tool: "gitleaks", Repository: repoA, Component: "api",
			Location: sarif.Location{URI: "config.env", StartLine: 1}, Message: "held at the minimum"},
		// Rated high by its scanner, so the floor moved nothing.
		{RuleID: "rated-key", Level: sarif.LevelError, Priority: "P1",
			Tool: "gitleaks", Repository: repoB, Component: "worker",
			Location: sarif.Location{URI: "deploy.env", StartLine: 2}, Message: "rated high"},
		// Held at high and ranked at the context floor: the tier is what decided the band.
		{RuleID: "tiered-key", Level: sarif.LevelWarning, Priority: "P1", SeverityFloor: sarif.SeverityHigh,
			PriorityFloor: floorReason,
			Tool:          "gitleaks", Repository: repoB, Component: "worker",
			Location: sarif.Location{URI: "ci.env", StartLine: 3}, Message: "ranked at the context floor"},
	}
	sca := []sarif.Result{
		// Deprecation raised low to medium, then the verdict lowered it back to low.
		{RuleID: "CVE-2099-0003", Level: sarif.LevelNote, Score: 2.0, HasScore: true, Priority: "P4",
			Tool: "trivy", Repository: repoB, Component: "worker",
			Location: sarif.Location{URI: "go.mod", StartLine: 4}, Message: "raised, then lowered",
			Escalation: &sarif.Escalation{From: sarif.SeverityLow, To: sarif.SeverityMedium,
				Signal: "deprecated", Detail: "deprecated", AsOf: "2026-11-05"},
			Reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
				Method: sarif.MethodCallGraph, RankedAs: sarif.SeverityLow}},
		// KEV raised it and overruled the verdict, which then lowered nothing.
		{RuleID: "CVE-2021-44228", Level: sarif.LevelError, Score: 7.5, HasScore: true, Priority: "P1",
			Tool: "trivy", Repository: repoA, Component: "api",
			Location: sarif.Location{URI: "go.mod", StartLine: 5}, Message: "raised over the verdict",
			Escalation: &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical,
				Signal: "kev", Detail: "on KEV", AsOf: "2026-11-05"},
			Reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
				Method: sarif.MethodCallGraph}},
	}
	return Data{
		Project:     "acme",
		Release:     saga.Release{Version: "1.0.0"},
		MinPriority: "P4",
		View:        ViewFindings,
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"sca":     {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: sca}},
			"secrets": {Control: "secrets", Report: sarif.Report{Tool: "gitleaks", Results: secrets}},
		}},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "sca", Verdict: norn.Fail},
			{Control: "secrets", Verdict: norn.Fail},
		}},
	}
}

// markCase is one finding, the severity printed beside its band, and the mark it carries, or ""
// where it carries none. absent is a mark that must not appear on it.
type markCase struct {
	rule, severity, mark, absent string
}

var markCases = []markCase{
	{rule: "floored-key", severity: "high", mark: "↑ minimum"},
	{rule: "rated-key", severity: "high", absent: "minimum"},
	{rule: "tiered-key", severity: "high", mark: "↑ floor", absent: "minimum"},
	{rule: "CVE-2099-0003", severity: "low", mark: "↓ unreachable", absent: "deprecated"},
	{rule: "CVE-2021-44228", severity: "critical", mark: "↑ KEV", absent: "unreachable"},
}

// The console names the mark at the head of the line under the row.
func TestTheConsoleMarksTheMoveThatDecidedTheSeverity(t *testing.T) {
	var out bytes.Buffer
	if err := (consoleReporter{}).Render(&out, marksData()); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out.String(), "\n")
	for _, c := range markCases {
		at := -1
		for i, line := range lines {
			if strings.Contains(line, c.rule) {
				at = i
				break
			}
		}
		if at < 0 || at+1 >= len(lines) {
			t.Fatalf("%s: no console row with a line under it:\n%s", c.rule, out.String())
		}
		row, under := lines[at], lines[at+1]
		if fields := strings.Fields(row); len(fields) < 2 || fields[1] != c.severity {
			t.Errorf("%s: console row %q, want severity %q beside the band", c.rule, row, c.severity)
		}
		mark := strings.Fields(under)
		got := ""
		if len(mark) >= 2 && (mark[0] == "↑" || mark[0] == "↓" || mark[0] == "↩") {
			got = mark[0] + " " + mark[1]
		}
		if got != c.mark {
			t.Errorf("%s: console mark %q, want %q, in\n%s\n%s", c.rule, got, c.mark, row, under)
		}
		if c.absent != "" && strings.Contains(under, c.absent) {
			t.Errorf("%s: the line under the row says %q:\n%s", c.rule, c.absent, under)
		}
	}
}

// Markdown writes the mark after the severity, in the console's words.
func TestMarkdownMarksTheMoveThatDecidedTheSeverity(t *testing.T) {
	var out bytes.Buffer
	if err := (markdownReporter{}).Render(&out, marksData()); err != nil {
		t.Fatal(err)
	}
	for _, c := range markCases {
		row := lineNaming(out.String(), c.rule)
		if row == "" {
			t.Fatalf("%s: no markdown row:\n%s", c.rule, out.String())
		}
		want := "| " + c.severity + " |"
		if c.mark != "" {
			want = "| " + c.severity + " " + c.mark + " |"
		}
		if !strings.Contains(row, want) {
			t.Errorf("%s: markdown row %q, want %q", c.rule, row, want)
		}
		if c.absent != "" && strings.Contains(row, c.absent) {
			t.Errorf("%s: markdown row %q says %q", c.rule, row, c.absent)
		}
	}
}

// The HTML report draws the mark on the row's second line, with the glyph apart from the label.
func TestTheHTMLReportMarksTheMoveThatDecidedTheSeverity(t *testing.T) {
	page := renderHTML(t, marksData())
	for _, c := range markCases {
		start := strings.Index(page, `data-q="`+strings.ToLower(c.rule)+` `)
		if start < 0 {
			t.Fatalf("%s: no row", c.rule)
		}
		row := page[start:]
		if end := strings.Index(row, `<div class="f" `); end >= 0 {
			row = row[:end]
		}
		if !strings.Contains(row, `class="sev sev-`+c.severity+`"`) && !strings.Contains(row, `sev-`+c.severity) {
			t.Errorf("%s: the row does not print severity %q", c.rule, c.severity)
		}
		if c.mark == "" {
			if strings.Contains(row, `class="moved`) {
				t.Errorf("%s: the row carries a mark, want none", c.rule)
			}
		} else {
			glyph, label, _ := strings.Cut(c.mark, " ")
			want := `<span class="g">` + glyph + `</span>` + label + `</span>`
			if !strings.Contains(row, want) {
				t.Errorf("%s: the row lacks the mark %q", c.rule, want)
			}
		}
		if c.absent != "" && strings.Contains(row, `</span>`+c.absent+`</span>`) {
			t.Errorf("%s: the row's mark is %q", c.rule, c.absent)
		}
	}
}

// The same choice, read from the finding the renderers share, for the cases a fixture of whole
// results does not reach.
func TestTheMarkIsTheMoveThatDecidedTheSeverity(t *testing.T) {
	deprecated := &sarif.Escalation{Signal: "deprecated", From: "low", To: "medium"}
	lowered := &sarif.Reachability{State: sarif.ReachabilityUnreachable, RankedAs: "low"}
	for _, c := range []struct {
		name, mark string
		f          finding
	}{
		{"held at the minimum", "minimum", finding{severityFloor: sarif.SeverityHigh}},
		{"held at the minimum, then raised", "deprecated",
			finding{severityFloor: sarif.SeverityHigh, escalation: deprecated}},
		{"held at the minimum, then lowered", "unreachable",
			finding{severityFloor: sarif.SeverityHigh, reachability: lowered}},
		{"raised, lowered and ranked at the context floor", "floor",
			finding{escalation: deprecated, reachability: lowered, priorityFloor: "floor"}},
		{"held at the minimum, from a commit", "minimum",
			finding{severityFloor: sarif.SeverityHigh, historical: true}},
	} {
		m := movedBy(c.f)
		if m == nil {
			t.Errorf("%s: no mark, want %q", c.name, c.mark)
			continue
		}
		if m.label != c.mark {
			t.Errorf("%s: mark %q, want %q", c.name, m.label, c.mark)
		}
	}
}
