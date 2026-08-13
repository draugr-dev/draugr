package diff

import (
	"bytes"
	"encoding/json"
	"slices"
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

// Every advertised format renders.
//
// A count told us the list had the length somebody last wrote down, which is true of a list with
// the wrong names in it and of one whose newest entry errors. `--format` help and the
// unknown-format error are both built from this list, so it has to be the list that works.
func TestFormats(t *testing.T) {
	got := Formats()
	if len(got) == 0 {
		t.Fatal("Formats() is empty")
	}
	if !slices.IsSorted(got) {
		t.Errorf("Formats() = %v, want sorted", got)
	}
	for _, f := range got {
		if err := Render(&bytes.Buffer{}, f, Result{}); err != nil {
			t.Errorf("advertised format %q does not render: %v", f, err)
		}
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
	// error → high and warning → medium when no score says otherwise; note lands in low.
	sc := countSeverities(rs)
	if sc.High != 1 || sc.Medium != 1 || sc.Low != 2 {
		t.Errorf("countSeverities = %+v", sc)
	}
	pc := countPriorities(rs)
	if pc.P1 != 1 || pc.P2 != 1 || pc.P3 != 1 || pc.P4 != 1 {
		t.Errorf("countPriorities = %+v", pc)
	}
}

// Narrowing applies to the new findings and nothing else.
//
// Fixed and unchanged are context for the reader, not things to act on, and a count of them that
// moved with a threshold would mean something different on every run. The unprioritized finding
// is kept on purpose: an empty Priority means prioritization did not run for it, not that it
// ranked low, and dropping it would hide the finding hardest to judge.
func TestNarrowNewKeepsOnlyTheBandAndOnlyForNew(t *testing.T) {
	r := Result{
		New: []sarif.Result{
			{RuleID: "URGENT", Priority: "P1"},
			{RuleID: "LATER", Priority: "P3"},
			{RuleID: "UNRANKED"},
		},
		Fixed:     []sarif.Result{{RuleID: "GONE", Priority: "P4"}},
		Unchanged: []sarif.Result{{RuleID: "OLD", Priority: "P4"}},
	}
	got := r.NarrowNew("P2")

	var ids []string
	for _, f := range got.New {
		ids = append(ids, f.RuleID)
	}
	if want := []string{"URGENT", "UNRANKED"}; !slices.Equal(ids, want) {
		t.Errorf("new = %v, want %v", ids, want)
	}
	if len(got.Fixed) != 1 || len(got.Unchanged) != 1 {
		t.Errorf("fixed/unchanged were narrowed: %d/%d", len(got.Fixed), len(got.Unchanged))
	}
	// No band, and an unrecognised one, both leave the result alone rather than emptying it.
	for _, band := range []string{"", "urgent"} {
		if n := len(r.NarrowNew(band).New); n != 3 {
			t.Errorf("band %q kept %d new findings, want all 3", band, n)
		}
	}
}

// The diff keys on what distinguishes a finding, not only where it is.
//
// identity deliberately drops the line and the level, because both drift without the finding
// changing. Component and repository are the opposite: they do not drift, they are the subject.
// Keyed without them a diff keeps whichever it saw first, and the other is reported as neither new
// nor fixed — it is simply absent, on the surface a reviewer is told to trust.
func TestIdentitySeparatesComponentsAndRepositories(t *testing.T) {
	at := func(component, repository string) sarif.Result {
		return sarif.Result{
			Tool: "gitleaks", RuleID: "generic-api-key", Level: sarif.LevelError,
			Message: "secret", Location: sarif.Location{URI: "config.py", StartLine: 1},
			Component: component, Repository: repository,
		}
	}
	head := sarif.Report{Results: []sarif.Result{
		at("frontend", "repo-a"), // same file, same rule, different component
		at("backend", "repo-a"),
		at("platform", "repo-b"), // and a third project entirely
	}}
	if got := Compare(sarif.Report{}, head); len(got.New) != 3 {
		t.Fatalf("new = %d, want 3 — one per component/repository", len(got.New))
	}

	// And a finding that only moved is still the same finding: the line is not part of identity.
	moved := at("frontend", "repo-a")
	moved.Location.StartLine = 99
	same := Compare(
		sarif.Report{Results: []sarif.Result{at("frontend", "repo-a")}},
		sarif.Report{Results: []sarif.Result{moved}},
	)
	if len(same.Unchanged) != 1 || len(same.New) != 0 {
		t.Errorf("a finding that moved lines read as new: %d new, %d unchanged", len(same.New), len(same.Unchanged))
	}
}

// A code-scanning upload carries only what the reviewed checkout can anchor.
//
// Paths are repository-relative, so a finding from another repository resolves to a same-named
// file here — an annotation on a line that does not have that problem. Findings belonging to no
// repository are kept: an image finding is located at an image reference, and dropping those would
// take most of a container scan off the surface a reviewer reads.
func TestOnlyRepositoryKeepsWhatThisCheckoutCanAnchor(t *testing.T) {
	r := Result{New: []sarif.Result{
		{RuleID: "HERE", Repository: "https://github.com/acme/web.git"},
		{RuleID: "ELSEWHERE", Repository: "https://github.com/acme/api.git"},
		{RuleID: "NO-REPO"}, // an image finding: no checkout, no path to anchor
	}}
	got := r.OnlyRepository("https://github.com/acme/web")

	var ids []string
	for _, f := range got.New {
		ids = append(ids, f.RuleID)
	}
	if want := []string{"HERE", "NO-REPO"}; !slices.Equal(ids, want) {
		t.Errorf("new = %v, want %v", ids, want)
	}
	// No repository asked for means no filtering, so every other caller is unaffected.
	if n := len(r.OnlyRepository("").New); n != 3 {
		t.Errorf("an empty reference filtered anyway: %d of 3 kept", n)
	}
}

func TestOnlyRepositoryTellsSiblingGroupsApart(t *testing.T) {
	// Two teams, one repository name. On a forge that nests groups this is ordinary, and the
	// filter has to survive it: keeping only the tail of each path makes both the same repository,
	// so a merge request annotates its own files with another team's findings — real findings, on
	// a plausible line, describing code this checkout does not contain.
	r := Result{New: []sarif.Result{
		{RuleID: "OURS", Repository: "https://gitlab.com/payments/backend/api.git"},
		{RuleID: "THEIRS", Repository: "https://gitlab.com/platform/backend/api.git"},
	}}
	got := r.OnlyRepository("https://gitlab.com/payments/backend/api")

	var ids []string
	for _, f := range got.New {
		ids = append(ids, f.RuleID)
	}
	if want := []string{"OURS"}; !slices.Equal(ids, want) {
		t.Errorf("new = %v, want %v", ids, want)
	}
}
