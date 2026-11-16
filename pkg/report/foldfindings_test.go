package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// sastResult is a gosec finding at P2 in one file and line.
func sastResult(rule, uri string, line int) sarif.Result {
	return sarif.Result{Tool: "gosec", RuleID: rule, Level: sarif.LevelWarning, Message: "Integer overflow conversion",
		Control: "sast", Priority: "P2", Location: sarif.Location{URI: uri, StartLine: line}}
}

// sastData is a run whose sast control reported results.
func sastData(results ...sarif.Result) Data {
	return Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Report: sarif.Report{Results: results}}}}}
}

// manyOfOneRule is twelve G115 findings across four files and one G204, which ranks below them.
func manyOfOneRule() []sarif.Result {
	var rs []sarif.Result
	for i := range 12 {
		rs = append(rs, sastResult("G115", fmt.Sprintf("gen/file%d.go", i%4), 10+i))
	}
	g204 := sastResult("G204", "main.go", 3)
	g204.Priority = "P3"
	return append(rs, g204)
}

// One rule's findings at one band in one component and repository share the row of the first of
// them, which counts them and the files they are in beside the rule and keeps the first's location.
// The heading counts findings, every one of them where every row fits.
func TestARuleWithManyFindingsFoldsIntoOneRow(t *testing.T) {
	out := renderWith(t, consoleReporter{}, sastData(manyOfOneRule()...))
	t.Logf("rendered:\n%s", out)
	for _, want := range []string{
		"FIX FIRST  13 findings, by priority\n",
		"G115 · 12 findings in 4 files\n",
		"      gen/file0.go:10\n",
		"  P3  ",
		"--top 0                                  every finding, one row each",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the console does not hold %q", want)
		}
	}
	if n := strings.Count(out, "G115"); n != 1 {
		t.Errorf("G115 is on %d rows, want one", n)
	}
	if strings.Contains(out, "not listed") {
		t.Error("a list whose every row fits says something was not listed")
	}
}

// A row standing for findings in one file says how many and names no file count.
func TestAFoldInOneFileCountsNoFiles(t *testing.T) {
	out := renderWith(t, consoleReporter{}, sastData(sastResult("G115", "a.go", 1), sastResult("G115", "a.go", 2)))
	if !strings.Contains(out, "G115 · 2 findings\n") {
		t.Errorf("the row does not count its findings alone:\n%s", out)
	}
}

// Where the row cap cuts a folded list, the heading counts the findings the rows stand for of all of
// them, never the rows, and the line under the list counts both what is left.
func TestACutFoldedListCountsFindingsAndRows(t *testing.T) {
	var rs []sarif.Result
	for r := range 12 {
		for i := range 3 {
			rs = append(rs, sastResult(fmt.Sprintf("G%d", 100+r), "main.go", r*10+i+1))
		}
	}
	out := renderWith(t, consoleReporter{}, sastData(rs...))
	t.Logf("rendered:\n%s", out)
	for _, want := range []string{
		"FIX FIRST  30 of 36 findings, by priority\n",
		"\n… and 2 more rows, 6 findings, not listed.\n",
		"--top 0                                  every finding, one row each",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the console does not hold %q", want)
		}
	}
	if strings.Contains(out, "top 10") {
		t.Error("the heading of a folded list counts its rows")
	}

	// One more row standing for one finding is said once, as findings.
	rs = append(rs, sastResult("G999", "main.go", 999))
	if out := renderWith(t, consoleReporter{}, sastData(rs...)); !strings.Contains(out, "\n… and 3 more rows, 7 findings, not listed.\n") {
		t.Errorf("tail of a cut folded list:\n%s", out)
	}
}

// Where the rows left out are one finding each, the line under the list counts them once.
func TestACutUnfoldedListCountsFindingsOnce(t *testing.T) {
	var rs []sarif.Result
	for r := range 11 {
		rs = append(rs, sastResult(fmt.Sprintf("G%d", 100+r), "main.go", r+1))
	}
	out := renderWith(t, consoleReporter{}, sastData(rs...))
	for _, want := range []string{"FIX FIRST  10 of 11 findings, by priority\n", "\n… and 1 more finding, not listed.\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("the console does not hold %q:\n%s", want, out)
		}
	}
}

// --top 0 lists every finding on a row of its own, and so does the compact view.
func TestTopZeroAndCompactListEveryFinding(t *testing.T) {
	d := sastData(manyOfOneRule()...)
	d.TopN = -1
	out := renderWith(t, consoleReporter{}, d)
	if strings.Contains(out, "findings in") || strings.Count(out, "G115") != 12 {
		t.Errorf("--top 0 folded the findings:\n%s", out)
	}
	if !strings.Contains(out, "FIX FIRST  13 findings, by priority") {
		t.Errorf("--top 0 heading:\n%s", out)
	}

	d = sastData(manyOfOneRule()...)
	d.View = ViewCompact
	out = renderWith(t, consoleReporter{}, d)
	if strings.Contains(out, "findings in") || strings.Count(out, "G115") != 10 {
		t.Errorf("the compact view folded the findings:\n%s", out)
	}
}

// A fold never joins findings the ranking keeps apart, or findings two owners, two repositories or
// two upgrades answer: each of these pairs stays two rows.
func TestAFoldKeepsApartWhatTheRowCannotSay(t *testing.T) {
	base := finding{ruleID: "G115", priority: "P2", component: "api", repository: "https://example.com/a.git",
		location: "a.go:1", pkg: &sarif.Package{Name: "libssl3", FixedVersion: "3.0.17"}}
	with := func(change func(*finding)) finding {
		f := base
		f.location = "b.go:2"
		change(&f)
		return f
	}
	for _, c := range []struct {
		name  string
		other finding
		rows  int
	}{
		{"the same rule, band, component, repository and package", with(func(*finding) {}), 1},
		{"a test file", with(func(f *finding) { f.nonShipping = "test" }), 2},
		{"generated code", with(func(f *finding) { f.aside = sarif.AsideGenerated }), 2},
		{"another band", with(func(f *finding) { f.priority = "P3" }), 2},
		{"another rule", with(func(f *finding) { f.ruleID = "G204" }), 2},
		{"another component", with(func(f *finding) { f.component = "web" }), 2},
		{"another repository", with(func(f *finding) { f.repository = "https://example.com/b.git" }), 2},
		{"another package", with(func(f *finding) { f.pkg = &sarif.Package{Name: "openssl", FixedVersion: "3.0.17"} }), 2},
		{"another fix", with(func(f *finding) { f.pkg = &sarif.Package{Name: "libssl3", FixedVersion: "3.0.18"} }), 2},
	} {
		if rows := foldFindings([]finding{base, c.other}); len(rows) != c.rows {
			t.Errorf("%s: %d rows, want %d", c.name, len(rows), c.rows)
		}
	}
}

// A fold never joins a finding in shipped code to one in a test, in the console as rendered: the
// test's finding keeps a row of its own, after the shipped ones.
func TestAFoldNeverJoinsShippedCodeAndATest(t *testing.T) {
	inTest := sastResult("G115", "internal/x/x_test.go", 9)
	inTest.NonShipping = "test"
	out := renderWith(t, consoleReporter{}, sastData(sastResult("G115", "a.go", 1), sastResult("G115", "b.go", 2), inTest))
	t.Logf("rendered:\n%s", out)
	if !strings.Contains(out, "G115 · 2 findings in 2 files\n") || strings.Count(out, "G115") != 2 ||
		!strings.Contains(out, "x_test.go:9 · test") {
		t.Error("the test's finding is not on a row of its own")
	}
}

// Two components and two repositories each keep their rows apart in the console as rendered.
func TestAFoldNeverJoinsTwoComponentsOrTwoRepositories(t *testing.T) {
	at := func(component, repository string, line int) sarif.Result {
		r := sastResult("G115", "main.go", line)
		r.Component, r.Repository = component, repository
		return r
	}
	out := renderWith(t, consoleReporter{}, sastData(
		at("api", "https://example.com/a.git", 1), at("api", "https://example.com/a.git", 2),
		at("api", "https://example.com/b.git", 3), at("web", "https://example.com/a.git", 4)))
	t.Logf("rendered:\n%s", out)
	if strings.Count(out, "G115") != 3 || strings.Count(out, "G115 · 2 findings\n") != 1 {
		t.Error("two components or two repositories share a row")
	}
}

// The row of a fold is where the first of its findings ranked, and a finding between them keeps its
// place after it.
func TestAFoldKeepsTheRankingsOrder(t *testing.T) {
	fs := []finding{
		{ruleID: "A", priority: "P1", location: "a.go:1"},
		{ruleID: "B", priority: "P1", location: "b.go:1"},
		{ruleID: "A", priority: "P1", location: "c.go:1"},
	}
	rows := foldFindings(fs)
	if len(rows) != 2 || rows[0].ruleID != "A" || rows[1].ruleID != "B" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].repeats != 1 || rows[0].repeatFiles != 2 || rows[0].location != "a.go:1" {
		t.Errorf("the fold's row = repeats %d, files %d, at %s", rows[0].repeats, rows[0].repeatFiles, rows[0].location)
	}
}

// Under --view actions, a run whose findings would fold offers --top 0 with --view findings, since
// the findings view alone no longer lists one each.
func TestTheActionsViewOffersEveryFindingWhenTheyFold(t *testing.T) {
	d := sastData(manyOfOneRule()...)
	d.View = ViewActions
	out := renderWith(t, consoleReporter{}, d)
	if !strings.Contains(out, "--view findings --top 0") {
		t.Errorf("the actions view does not offer every finding:\n%s", out)
	}
}

// The id of a signer finding keeps its count on the title line.
func TestAFoldedSignerRowCountsItsFindings(t *testing.T) {
	f := finding{ruleID: "provenance-unexpected-identity", priority: "P1",
		message: "Signed by https://github.com/o/r/.github/workflows/release.yml@refs/heads/main, not o/r.",
		repeats: 1, repeatFiles: 2}
	var b strings.Builder
	writeBlockHead(&b, tui.Plain(), f, 120)
	if !strings.Contains(b.String(), "not o/r · 2 findings in 2 files\n") {
		t.Errorf("the signer row does not count its findings:\n%s", b.String())
	}
}

// A long rule id with a count moves under the count rather than pushing it off the line.
func TestALongFoldedRuleTakesTheLineBeneath(t *testing.T) {
	f := finding{ruleID: strings.Repeat("r", 60), priority: "P2", repeats: 2, repeatFiles: 1}
	var b strings.Builder
	writeBlockHead(&b, tui.Plain(), f, 70)
	lines := strings.Split(b.String(), "\n")
	if !strings.HasSuffix(lines[0], "3 findings") || strings.TrimSpace(lines[1]) != f.ruleID {
		t.Errorf("head:\n%s", b.String())
	}
}
