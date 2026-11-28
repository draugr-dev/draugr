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
	"github.com/draugr-dev/draugr/pkg/tui"
)

// listing is a console run up to its closer, for a test that counts what the list printed: the
// closer names the first row again.
func listing(out string) string {
	if i := strings.LastIndex(out, "\nDRAUGR  "); i >= 0 {
		return out[:i]
	}
	return out
}

// closer is the lines after the closer's blank line, the last block of a console run.
func closer(t *testing.T, out string) []string {
	t.Helper()
	i := strings.LastIndex(out, "\n\nDRAUGR  ")
	if i < 0 {
		t.Fatalf("no closer after a blank line:\n%s", out)
	}
	return strings.Split(strings.TrimSuffix(out[i+2:], "\n"), "\n")
}

// A failing run ends on its verdict and counts, the controls and caveats that fail it, and the first
// row of FIX FIRST: its rule, its fix in the row's words, and where it is.
func TestAFailingRunEndsOnItsVerdictAndWhereToStart(t *testing.T) {
	sca := sarif.Result{Tool: "trivy", RuleID: "CVE-2019-10906", Level: sarif.LevelError, Control: "sca", Priority: "P1",
		Location: sarif.Location{URI: "app/requirements.txt", StartLine: 5},
		Package:  &sarif.Package{Name: "jinja2", Version: "2.10", FixedVersion: "2.10.1"}}
	d := Data{
		FailOnCaveats: []saga.CaveatKind{saga.CaveatUnreadFiles},
		Run: engine.Result{
			Controls: map[string]plugin.ControlResult{
				"sca":  {Control: "sca", Report: sarif.Report{Results: []sarif.Result{sca}}},
				"sast": {Control: "sast", Report: sarif.Report{Results: []sarif.Result{sastResult("G115", "main.go", 3)}}},
			},
			ScanErrors: map[string][]string{"dast": {"nuclei: connection refused"}},
			Inputs: []engine.InputCoverage{{Component: "api", Control: "licenses",
				Unread: []engine.UnreadInput{{Repository: "api", Path: "a/go.mod", Reason: "no lockfile"}}}},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "sast", Verdict: norn.Fail}, {Control: "sca", Verdict: norn.Fail}, {Control: "secrets", Verdict: norn.Pass},
		}},
	}
	got := closer(t, renderConsole(t, d))
	want := []string{
		"DRAUGR  FAIL  1 P1 1 P2 0 P3 0 P4",
		"  sast and sca fail · dast errored · 1 caveat fails the run",
		"  FIX FIRST  CVE-2019-10906 · jinja2 2.10 → 2.10.1 · app/requirements.txt:5",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("closer:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A clean run that was narrowed ends on its PASS and says what it covered, so the last line read on
// its own does not claim more than the run checked.
func TestACleanScopedRunEndsOnPassAndItsScope(t *testing.T) {
	d := Data{Scope: &Scope{Controls: []string{"provenance"}},
		Verdict: norn.Result{Verdict: norn.Pass, Controls: []norn.ControlOutcome{{Control: "provenance", Verdict: norn.Pass}}}}
	got := closer(t, renderConsole(t, d))
	if len(got) != 1 || got[0] != "DRAUGR  PASS  no findings · scoped to the provenance control" {
		t.Errorf("closer = %q", got)
	}
}

// A run that ranked nothing has no bands to repeat, and counts its findings instead.
func TestAnUnrankedRunCountsItsFindingsInTheCloser(t *testing.T) {
	r := sastResult("G115", "main.go", 3)
	r.Priority = ""
	got := closer(t, renderConsole(t, sastData(r)))
	if got[0] != "DRAUGR  PASS  1 finding" {
		t.Errorf("closer = %q", got)
	}
}

// Nothing on the FIX FIRST line is cut, because a reader copies its rule and location into
// config.exclude, which matches them only whole. A line that does not fit moves the location under
// the rule instead.
func TestTheCloserKeepsTheRuleAndLocationWholeWhereTheyDoNotFit(t *testing.T) {
	long := "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag"
	r := sastResult(long, ".github/workflows/deeply/nested/directory/ci.yml", 12)
	t.Setenv("COLUMNS", "")
	got := closer(t, renderConsole(t, sastData(r)))
	want := []string{
		"DRAUGR  PASS  0 P1 1 P2 0 P3 0 P4",
		"  FIX FIRST  " + long,
		"             fix change the code · .github/workflows/deeply/nested/directory/ci.yml:12",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("closer:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, line := range got {
		for _, field := range strings.Fields(line) {
			if strings.Contains(field, "mutable-action-tag") &&
				!(saga.ExcludeRule{Rules: []string{field}}).Matches("ci.yml", long) {
				t.Errorf("the closer prints %q, which config.exclude does not match to the rule", field)
			}
		}
	}

	// A rule and fix that fit keep the line, and only the location moves under the rule.
	mid := sastResult("javascript.express.security.audit.xss.mustache", "web/src/views/templates/partials/header.js", 3)
	got = closer(t, renderConsole(t, sastData(mid)))
	if len(got) != 3 || got[1] != "  FIX FIRST  javascript.express.security.audit.xss.mustache · fix change the code" ||
		got[2] != "             web/src/views/templates/partials/header.js:3" {
		t.Errorf("a rule and fix that fit: %q", got)
	}

	// A terminal narrower than messageWidth moves it too, where the same line would fit in 96.
	short := sastResult("G115", "internal/report/console.go", 120)
	t.Setenv("COLUMNS", "50")
	got = closer(t, renderConsole(t, sastData(short)))
	if got[len(got)-1] != "             internal/report/console.go:120" {
		t.Errorf("at 50 columns the location stays on the rule's line: %q", got)
	}
	t.Setenv("COLUMNS", "120")
	got = closer(t, renderConsole(t, sastData(short)))
	if got[len(got)-1] != "  FIX FIRST  G115 · fix change the code · internal/report/console.go:120" {
		t.Errorf("at 120 columns: %q", got)
	}
}

// The fix says what the row says: the image to move to, the package and the release, or the phrase.
func TestTheCloserSaysTheFixInTheRowsWords(t *testing.T) {
	col := tui.Plain()
	pkg := finding{pkg: &sarif.Package{Name: "jinja2", Version: "2.10", FixedVersion: "2.10.1"}}
	if plain, painted := closerFix(col, pkg); plain != "jinja2 2.10 → 2.10.1" || painted != plain {
		t.Errorf("package: %q, %q", plain, painted)
	}
	none := finding{pkg: &sarif.Package{Name: "left-pad", Version: "1.0.0"}}
	if plain, _ := closerFix(col, none); !strings.HasPrefix(plain, "left-pad 1.0.0 fix ") {
		t.Errorf("no release: %q", plain)
	}
	code := finding{control: "sast"}
	if plain, _ := closerFix(col, code); plain != "fix change the code" {
		t.Errorf("code: %q", plain)
	}
}

// The closer is set off by one blank line whatever the output before it ended on: a line, a blank
// line, a line without its newline, or nothing at all.
func TestTheCloserIsSetOffByOneBlankLine(t *testing.T) {
	for _, before := range []string{"", "TRY\n", "TRY\n\n", "TRY"} {
		var buf bytes.Buffer
		e := &endWriter{w: &buf}
		_, _ = e.Write([]byte(before))
		writeCloser(e, tui.Plain(), summary{}, Data{}, nil, blobLinker{})
		want := "DRAUGR  PASS  no findings\n"
		if before != "" {
			want = strings.TrimRight(before, "\n") + "\n\n" + want
		}
		if buf.String() != want {
			t.Errorf("after %q: %q, want %q", before, buf.String(), want)
		}
	}
	// One byte at a time, as a writer may be handed it.
	var buf bytes.Buffer
	e := &endWriter{w: &buf}
	for _, b := range []byte("TRY\n\n") {
		_, _ = e.Write([]byte{b})
	}
	if e.last != "\n\n" {
		t.Errorf("last = %q", e.last)
	}
}
