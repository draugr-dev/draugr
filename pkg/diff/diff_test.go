package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

func res(tool, rule string, level sarif.Level, uri string, line int, priority string) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: level, Message: rule + " msg",
		Location: sarif.Location{URI: uri, StartLine: line}, Priority: priority,
	}
}

func TestCompareClassifies(t *testing.T) {
	base := sarif.Report{Results: []sarif.Result{
		res("trivy", "CVE-1", sarif.LevelError, "img", 0, "P1"),
		res("trivy", "CVE-2", sarif.LevelWarning, "img", 0, "P3"),
	}}
	head := sarif.Report{Results: []sarif.Result{
		res("trivy", "CVE-1", sarif.LevelError, "img", 0, "P1"), // unchanged
		res("trivy", "CVE-3", sarif.LevelError, "img", 0, "P2"), // new
	}}
	d := Compare(base, head)
	if len(d.New) != 1 || d.New[0].RuleID != "CVE-3" {
		t.Errorf("new = %v", d.New)
	}
	if len(d.Fixed) != 1 || d.Fixed[0].RuleID != "CVE-2" {
		t.Errorf("fixed = %v", d.Fixed)
	}
	if len(d.Unchanged) != 1 || d.Unchanged[0].RuleID != "CVE-1" {
		t.Errorf("unchanged = %v", d.Unchanged)
	}
}

// A finding that moves lines must stay "unchanged", not read as fixed+new.
func TestLineDriftIsUnchanged(t *testing.T) {
	base := sarif.Report{Results: []sarif.Result{res("semgrep", "R1", sarif.LevelWarning, "a.go", 10, "P2")}}
	head := sarif.Report{Results: []sarif.Result{res("semgrep", "R1", sarif.LevelWarning, "a.go", 99, "P2")}}
	d := Compare(base, head)
	if len(d.New) != 0 || len(d.Fixed) != 0 || len(d.Unchanged) != 1 {
		t.Errorf("line drift should be unchanged: new=%d fixed=%d unchanged=%d", len(d.New), len(d.Fixed), len(d.Unchanged))
	}
}

// A re-scored finding (level change) is still the same underlying issue.
func TestLevelChangeIsUnchanged(t *testing.T) {
	base := sarif.Report{Results: []sarif.Result{res("trivy", "CVE-9", sarif.LevelWarning, "img", 0, "P3")}}
	head := sarif.Report{Results: []sarif.Result{res("trivy", "CVE-9", sarif.LevelError, "img", 0, "P1")}}
	d := Compare(base, head)
	if len(d.Unchanged) != 1 {
		t.Errorf("level re-score should be unchanged, got new=%d fixed=%d", len(d.New), len(d.Fixed))
	}
}

func TestNewSortedMostUrgentFirst(t *testing.T) {
	head := sarif.Report{Results: []sarif.Result{
		res("t", "LOW", sarif.LevelNote, "x", 0, "P4"),
		res("t", "HIGH", sarif.LevelError, "x", 0, "P1"),
	}}
	d := Compare(sarif.Report{}, head)
	if d.New[0].RuleID != "HIGH" {
		t.Errorf("expected most-urgent first, got %s", d.New[0].RuleID)
	}
}

func TestGateNewBySeverity(t *testing.T) {
	d := Result{New: []sarif.Result{
		res("t", "E", sarif.LevelError, "x", 0, ""),
		res("t", "W", sarif.LevelWarning, "x", 0, ""),
	}}
	if got := d.GateNew(sarif.LevelError, ""); len(got) != 1 || got[0].RuleID != "E" {
		t.Errorf("fail-on-new error should trip on 1, got %v", got)
	}
	if got := d.GateNew(sarif.LevelWarning, ""); len(got) != 2 {
		t.Errorf("fail-on-new warning should trip on 2, got %d", len(got))
	}
	if got := d.GateNew("", ""); len(got) != 0 {
		t.Errorf("empty thresholds should trip on nothing, got %d", len(got))
	}
}

func TestGateNewByPriority(t *testing.T) {
	d := Result{New: []sarif.Result{
		res("t", "A", sarif.LevelError, "x", 0, "P1"),
		res("t", "B", sarif.LevelError, "x", 0, "P3"),
	}}
	if got := d.GateNew("", "P2"); len(got) != 1 || got[0].RuleID != "A" {
		t.Errorf("fail-on-new-priority P2 should trip only on P1, got %v", got)
	}
	// Unprioritized new findings never trip a priority gate.
	d2 := Result{New: []sarif.Result{res("t", "C", sarif.LevelError, "x", 0, "")}}
	if got := d2.GateNew("", "P4"); len(got) != 0 {
		t.Errorf("unprioritized finding should not trip a priority gate, got %v", got)
	}
}

func TestRenderConsole(t *testing.T) {
	d := Compare(
		sarif.Report{Results: []sarif.Result{res("trivy", "OLD", sarif.LevelWarning, "img", 0, "P3")}},
		sarif.Report{Results: []sarif.Result{res("trivy", "NEW", sarif.LevelError, "img", 0, "P1")}},
	)
	var b bytes.Buffer
	if err := Render(&b, "console", d); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"Draugr diff —", "1 new", "New (1):", "NEW", "Fixed (1):", "OLD"} {
		if !strings.Contains(s, want) {
			t.Errorf("console diff missing %q\n%s", want, s)
		}
	}
}

func TestRenderMarkdownAndNoChange(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "markdown", Compare(sarif.Report{}, sarif.Report{})); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No change in the finding footprint") {
		t.Errorf("expected no-change message, got:\n%s", b.String())
	}
}

func TestRenderJSON(t *testing.T) {
	d := Compare(
		sarif.Report{},
		sarif.Report{Results: []sarif.Result{res("trivy", "NEW", sarif.LevelError, "img", 0, "P1")}},
	)
	var b bytes.Buffer
	if err := Render(&b, "json", d); err != nil {
		t.Fatal(err)
	}
	var doc jsonDiff
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("json diff not valid: %v", err)
	}
	if doc.Summary.New != 1 || doc.Summary.NewByPriority.P1 != 1 || len(doc.New) != 1 {
		t.Errorf("json summary wrong: %+v", doc.Summary)
	}
}

func TestRenderUnknownFormat(t *testing.T) {
	if err := Render(&bytes.Buffer{}, "bogus", Result{}); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestFormats(t *testing.T) {
	if got := Formats(); len(got) != 3 {
		t.Errorf("Formats() = %v", got)
	}
}

func TestRenderMarkdownWithFindings(t *testing.T) {
	d := Compare(
		sarif.Report{Results: []sarif.Result{res("gitleaks", "OLD", sarif.LevelError, "src/a.go", 5, "P2")}},
		sarif.Report{Results: []sarif.Result{res("semgrep", "NEW", sarif.LevelWarning, "src/b.go", 12, "P1")}},
	)
	var b bytes.Buffer
	if err := Render(&b, "markdown", d); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"### 🔺 New (1)", "`NEW`", "semgrep", "src/b.go:12", "### ✅ Fixed (1)", "`OLD`", "src/a.go:5"} {
		if !strings.Contains(s, want) {
			t.Errorf("markdown diff missing %q\n%s", want, s)
		}
	}
}

func TestSortTieBreaks(t *testing.T) {
	// Equal priority → higher score first; equal score → higher level; equal level → ruleID.
	withScore := func(rule string, score float64, level sarif.Level) sarif.Result {
		r := res("t", rule, level, "u", 0, "P2")
		r.Score, r.HasScore = score, true
		return r
	}
	head := sarif.Report{Results: []sarif.Result{
		withScore("B_LOWSCORE", 1.0, sarif.LevelError),
		withScore("A_HIGHSCORE", 9.0, sarif.LevelError),
	}}
	d := Compare(sarif.Report{}, head)
	if d.New[0].RuleID != "A_HIGHSCORE" {
		t.Errorf("higher score should sort first, got %s", d.New[0].RuleID)
	}

	// Equal priority + score → higher level first.
	lvl := sarif.Report{Results: []sarif.Result{
		res("t", "note", sarif.LevelNote, "u", 0, "P2"),
		res("t", "err", sarif.LevelError, "u", 0, "P2"),
	}}
	d2 := Compare(sarif.Report{}, lvl)
	if d2.New[0].RuleID != "err" {
		t.Errorf("higher level should sort first, got %s", d2.New[0].RuleID)
	}

	// All equal → ruleID ascending.
	tie := sarif.Report{Results: []sarif.Result{
		res("t", "zzz", sarif.LevelWarning, "u", 0, "P2"),
		res("t", "aaa", sarif.LevelWarning, "u", 0, "P2"),
	}}
	d3 := Compare(sarif.Report{}, tie)
	if d3.New[0].RuleID != "aaa" {
		t.Errorf("ruleID tie-break should sort ascending, got %s", d3.New[0].RuleID)
	}
}

func TestConsoleNoLocationAndUnprioritized(t *testing.T) {
	// A new finding with no location and no priority exercises loc("")/dash("") fallbacks.
	head := sarif.Report{Results: []sarif.Result{res("t", "R", sarif.LevelWarning, "", 0, "")}}
	var b bytes.Buffer
	if err := Render(&b, "console", Compare(sarif.Report{}, head)); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.Contains(s, "+ -") || !strings.Contains(s, "-\n") {
		t.Errorf("expected dash fallbacks for missing priority/location:\n%s", s)
	}
	// Unprioritized-only delta prints no priority breakdown lines.
	if strings.Contains(s, "New priorities:") {
		t.Errorf("unprioritized delta should not print priority lines:\n%s", s)
	}
}

func TestCountsAllBands(t *testing.T) {
	rs := []sarif.Result{
		res("t", "a", sarif.LevelError, "u", 0, "P1"),
		res("t", "b", sarif.LevelWarning, "u", 0, "P2"),
		res("t", "c", sarif.LevelNote, "u", 0, "P3"),
		res("t", "d", sarif.LevelNote, "u", 0, "P4"),
	}
	lc := countLevels(rs)
	if lc.Error != 1 || lc.Warning != 1 || lc.Note != 2 {
		t.Errorf("countLevels = %+v", lc)
	}
	pc := countPriorities(rs)
	if pc.P1 != 1 || pc.P2 != 1 || pc.P3 != 1 || pc.P4 != 1 {
		t.Errorf("countPriorities = %+v", pc)
	}
}
