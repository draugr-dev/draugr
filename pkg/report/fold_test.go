package report

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// lineAction is the action a scan makes of one finding at one line.
func lineAction(priority, component, repository, location, title string) action {
	f := finding{control: "sast", priority: priority, component: component, repository: repository, location: location}
	return action{key: lineKeyOf(f), title: title, priority: priority, control: "sast", component: component, findings: []finding{f}}
}

func TestRowsSayingTheSameThingFold(t *testing.T) {
	rows := foldLines([]action{
		lineAction("P1", "api", "r", "a.go:3", "Handle the returned error"),
		lineAction("P1", "api", "r", "b.go:1", "Pass outside data as query parameters, not in the SQL text"),
		lineAction("P1", "api", "r", "a.go:9", "Handle the returned error"),
	})
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].title != "Handle the returned error" || rows[0].lines != 2 || rows[0].count() != 2 {
		t.Errorf("first row: %q, %d lines, %d findings", rows[0].title, rows[0].lines, rows[0].count())
	}
	if rows[1].title != "Pass outside data as query parameters, not in the SQL text" {
		t.Errorf("a row should keep the place of its first line, got %q second", rows[1].title)
	}
}

// Each of these is a different owner or a different file, and a row that joined them would hand one
// person another's work or name a path in the wrong repository.
func TestRowsStayApartAcrossBandComponentAndRepository(t *testing.T) {
	const title = "Handle the returned error"
	for name, as := range map[string][]action{
		"band":       {lineAction("P1", "api", "r", "a.go:1", title), lineAction("P2", "api", "r", "a.go:2", title)},
		"component":  {lineAction("P1", "api", "r", "a.go:1", title), lineAction("P1", "web", "r", "a.go:2", title)},
		"repository": {lineAction("P1", "api", "one", "main.go:12", title), lineAction("P1", "api", "two", "main.go:12", title)},
	} {
		if rows := foldLines(as); len(rows) != 2 {
			t.Errorf("%s: got %d rows, want 2", name, len(rows))
		}
	}
}

// A line asking for a second change has a row of its own, because that row says so and the other does
// not.
func TestARowAskingForASecondChangeStaysApart(t *testing.T) {
	plain := lineAction("P1", "api", "r", "a.go:1", "Handle the returned error")
	also := lineAction("P1", "api", "r", "a.go:2", "Handle the returned error")
	also.summary = "Also: Use html/template if the response is HTML"
	if rows := foldLines([]action{plain, also}); len(rows) != 2 {
		t.Errorf("got %d rows, want 2", len(rows))
	}
}

func TestAnActionForARuleDoesNotFold(t *testing.T) {
	rule := action{key: "iac\x00KSV-0017", title: "Fix KSV-0017", priority: "P1", control: "iac",
		findings: []finding{{control: "iac", location: "a.yaml:1"}}}
	if rows := foldLines([]action{rule, rule}); len(rows) != 2 || rows[0].lines != 0 {
		t.Errorf("got %d rows, %d lines on the first", len(rows), rows[0].lines)
	}
}

// Folding reads the list it was given. report.json is written from the same actions, and keeps one per
// line.
func TestFoldingLeavesItsInputAlone(t *testing.T) {
	first := lineAction("P1", "api", "r", "a.go:1", "Handle the returned error")
	first.findings = append(make([]finding, 0, 4), first.findings...)
	as := []action{first, lineAction("P1", "api", "r", "a.go:2", "Handle the returned error")}
	foldLines(as)
	if as[0].count() != 1 || as[0].lines != 0 || as[1].count() != 1 {
		t.Errorf("input changed: %d and %d findings, %d lines", as[0].count(), as[1].count(), as[0].lines)
	}
	if got := foldLines(as)[0].findings[1].location; got != "a.go:2" {
		t.Errorf("second finding at %q", got)
	}
}

func foldedRow(locations ...string) action {
	a := action{key: lineKey, lines: len(locations)}
	for _, l := range locations {
		a.findings = append(a.findings, finding{location: l, repository: "https://example.com/r"})
	}
	return a
}

func TestAFoldedRowNamesItsLines(t *testing.T) {
	two := foldedRow("b.go:30", "a.go:9", "b.go:4", "a.go:9")
	long := foldedRow("b.go:30", "b.go:4", "long/path/to/a.go:9")
	for _, c := range []struct {
		name string
		a    action
		room int
		want string
	}{
		{"every line, each file once, numbers in order", two, 100, "b.go:4,30 · a.go:9"},
		{"the lines that do not fit are counted", long, 22, "b.go:4,30 · and 1 more"},
		{"counted from the first line that does not fit", long, 20, "b.go:4 · and 2 more"},
		{"a directory cut so a file is named", foldedRow("internal/deep/down/file.go:1", "x.go:2", "y.go:3"), 24, "…/file.go:1 · and 2 more"},
		{"the count goes when a file name alone fills the room", foldedRow("internal/deep/down/file.go:1", "x.go:2"), 14, "…/file.go:1"},
		{"one that fits needs no count", foldedRow("x.go:1", "x.go:2"), 8, "x.go:1,2"},
	} {
		if got := foldedPlaces(c.a, c.room); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// With no room at all the row still names a file rather than printing an empty place.
	if got := foldedPlaces(foldedRow("internal/file.go:1", "x.go:2"), 1); !strings.Contains(got, "file.go:1") {
		t.Errorf("no room: got %q", got)
	}
}

// A path in two repositories is two files, so a list spanning them says which.
func TestAFoldedRowNamesItsRepositoryWhereTheListSpansSeveral(t *testing.T) {
	a := foldedRow("x.go:1", "x.go:2")
	a.nameRepository = true
	if got := foldedPlaces(a, 200); !strings.Contains(got, "example.com/r") || !strings.Contains(got, "x.go:1,2") {
		t.Errorf("got %q", got)
	}
}

func TestAListCountsItsRowsAndTheirLines(t *testing.T) {
	line := func(path string, fingerprints ...string) action {
		a := lineAction("P1", "api", "r", path, "Handle the returned error")
		a.findings = nil
		if len(fingerprints) == 0 {
			fingerprints = []string{path}
		}
		for _, fp := range fingerprints {
			a.findings = append(a.findings, finding{control: "sast", priority: "P1", component: "api", repository: "r",
				location: path, fingerprint: fp})
		}
		return a
	}
	rule := action{key: "iac\x00x", title: "Fix x"}
	for _, c := range []struct {
		name string
		as   []action
		want string
	}{
		{"folded", []action{line("a.go:1", "1", "2"), line("a.go:2", "3")}, "1 action on 2 lines"},
		{"folded, a finding a line", []action{line("a.go:1", "1"), line("a.go:2", "2")}, "1 action"},
		{"nothing folded", []action{line("a.go:1")}, "1 action"},
		{"not every row is about lines", []action{line("a.go:1"), line("a.go:2"), rule}, "2 actions"},
	} {
		if got := listCount(c.as); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if !foldsAny([]action{line("a.go:1"), line("a.go:2")}) || foldsAny([]action{line("a.go:1")}) {
		t.Error("foldsAny disagrees with what folds")
	}
}

// A row standing for several lines counts them where they differ from its findings. Where every
// line holds one finding, the two counts are one number, said once.
func TestAConsoleRowSaysHowManyLinesItStandsFor(t *testing.T) {
	var b bytes.Buffer
	renderActions(&b, tui.Plain(), []action{
		lineAction("P3", "", "r", "a.go:1", "Handle the returned error"),
		lineAction("P3", "", "r", "a.go:2", "Handle the returned error"),
	}, false)
	out := b.String()
	if strings.Count(out, "Handle the returned error") != 1 {
		t.Errorf("the title should print once:\n%s", out)
	}
	if !strings.Contains(out, "      2 findings · a.go:1,2") || strings.Contains(out, "2 lines") {
		t.Errorf("want one count:\n%s", out)
	}
	if strings.Contains(out, "control sast") {
		t.Errorf("one control's rows should not repeat it:\n%s", out)
	}

	b.Reset()
	twice := lineAction("P3", "", "r", "a.go:1", "Handle the returned error")
	twice.findings = append(twice.findings, twice.findings[0])
	renderActions(&b, tui.Plain(), []action{twice, lineAction("P3", "", "r", "a.go:2", "Handle the returned error")}, false)
	if !strings.Contains(b.String(), "2 lines · 3 findings · a.go:1,2") {
		t.Errorf("want the lines named where they differ from the findings:\n%s", b.String())
	}
}

func TestRowsNameTheControlWhereAListSpansSeveral(t *testing.T) {
	var b bytes.Buffer
	other := lineAction("P3", "", "r", "b.go:1", "Pass outside data as query parameters, not in the SQL text")
	other.control = "iac"
	renderActions(&b, tui.Plain(), []action{lineAction("P3", "", "r", "a.go:1", "Handle the returned error"), other}, false)
	if !strings.Contains(b.String(), "control sast") || !strings.Contains(b.String(), "control iac") {
		t.Errorf("got:\n%s", b.String())
	}
}

// A row sits on one line at the widths a reader has, whatever it folds.
func TestAFoldedRowFitsItsWidth(t *testing.T) {
	var as []action
	for _, l := range []string{"internal/glance/config-fields.go:148", "internal/glance/config-fields.go:165", "internal/glance/templates.go:19"} {
		as = append(as, lineAction("P2", "", "r", l, "Check the value is safe before a template trusts it"))
	}
	t.Setenv("COLUMNS", "60")
	var b bytes.Buffer
	renderActions(&b, tui.Plain(), as, false)
	for _, line := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
		if n := utf8.RuneCountInString(line); n > 60 {
			t.Errorf("%d columns: %q", n, line)
		}
	}
}

// report.json records the row each action shares, so a consumer lists the actions as --view actions
// does without repeating the rule that decides which lines fold.
func TestEachActionRecordsTheRowItShares(t *testing.T) {
	withoutReasonedInstructions(t)
	res := func(rule, path string, line int, msg string) sarif.Result {
		return sarif.Result{Control: "sast", Tool: "gosec", RuleID: rule, Priority: "P3", Level: sarif.LevelWarning,
			Component: "api", Repository: demoRepository, Message: msg,
			Location: sarif.Location{URI: path, StartLine: line}}
	}
	const narrowing = "integer overflow conversion int -> uint32"
	got := ActionsFor(map[string]sarif.Report{"sast": {Results: []sarif.Result{
		res("G115", "dict/builder.go", 144, narrowing),
		res("G104", "main.go", 9, "Errors unhandled"),
		res("G115", "dict/builder.go", 150, narrowing),
		res("G115", "flate/deflate.go", 12, narrowing),
	}}})
	if len(got) != 4 {
		t.Fatalf("want an action per line, 4, got %d", len(got))
	}
	rows := map[string][]string{}
	for _, a := range got {
		rows[a.Row] = append(rows[a.Row], a.Where[0])
	}
	if len(rows[""]) != 1 || rows[""][0] != "main.go:9" {
		t.Errorf("an action no other line shares a row with should name none: %v", rows)
	}
	if len(rows) != 2 {
		t.Fatalf("want the G115 lines on one row, got rows %v", rows)
	}
	for row, where := range rows {
		if row == "" {
			continue
		}
		if len(where) != 3 {
			t.Errorf("row %s holds %v, want the three G115 lines", row, where)
		}
		var first Action
		for _, a := range got {
			if a.Row == row {
				first = a
				break
			}
		}
		if first.ID != row {
			t.Errorf("a row is named by its first action's id, %s, got %s", first.ID, row)
		}
	}
}

func TestALineNoOtherSharesARowWithIsOnItsOwn(t *testing.T) {
	as := []action{
		lineAction("P1", "api", "r", "a.go:3", "Handle the returned error"),
		lineAction("P1", "api", "r", "b.go:1", "Pass outside data as query parameters, not in the SQL text"),
		lineAction("P1", "api", "r", "a.go:9", "Handle the returned error"),
		{key: "rule\x00x", title: "Handle the returned error", priority: "P1", component: "api"},
	}
	if got, want := lineRows(as), []int{0, -1, 0, -1}; !slices.Equal(got, want) {
		t.Errorf("lineRows = %v, want %v", got, want)
	}
	if len(foldLines(as)) != 3 {
		t.Errorf("the rows lineRows describes should be the rows foldLines prints")
	}
}

// The heading over the lists leaves out a part one list holds whole, which that list's heading
// counts, and keeps a part two lists share.
func TestTheHeadingOverTheListsSaysNoCountOneListSays(t *testing.T) {
	act := func(kind skald.ActionKind, title, fp string) action {
		return action{key: fp, kind: kind, title: title, findings: []finding{{fingerprint: fp}}}
	}
	fix := act(skald.KindCode, "Pin actions to a full commit SHA", "1")
	query := act(skald.KindCode, "Pass outside data as query parameters", "2")
	key := act(skald.KindCredential, "Check for a credential, and rotate any you find", "3")
	url := act(skald.KindCode, "Check who can set the URL", "4")
	lists := func(as ...action) map[skald.ActionKind][]action {
		m := map[skald.ActionKind][]action{}
		for _, a := range as {
			m[a.kind] = append(m[a.kind], a)
		}
		return m
	}
	all := []action{fix, query, key, url}
	if got := acrossLists(all, lists(all...)); got != "2 checks on 2 findings" {
		t.Errorf("every change in one list, checks in two: got %q", got)
	}
	if got := acrossLists(all[:3], lists(all[:3]...)); got != "" {
		t.Errorf("every change in one list, every check in another: got %q, want no count", got)
	}
	bump := act(skald.KindBump, "Upgrade jinja2", "5")
	all = append(all, bump)
	if got := acrossLists(all, lists(all...)); got != "3 actions clear 3 findings · 2 checks on 2 more" {
		t.Errorf("changes in two lists: got %q", got)
	}
}

// A Check action ends in a change or in a recorded exclusion, which the actions view says once
// under its heading, and only on a run that has one.
func TestTheActionsViewSaysOnceHowACheckEnds(t *testing.T) {
	check := func(uri string, line int) sarif.Result {
		return sarif.Result{RuleID: "javascript.lang.security.detect-child-process.detect-child-process",
			Level: sarif.LevelError, Priority: "P2", Tool: "semgrep",
			Location: sarif.Location{URI: uri, StartLine: line}}
	}
	run := func(results ...sarif.Result) string {
		return renderConsole(t, Data{View: ViewActions, Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"sast": {Report: sarif.Report{Results: results}},
		}}})
	}
	withChecks := run(check("app/run.js", 12), check("app/jobs.js", 40))
	if n := strings.Count(withChecks, checkEnding); n != 1 {
		t.Errorf("the check's ending is said %d times, want once:\n%s", n, withChecks)
	}
	if !strings.Contains(withChecks, "Check who can set the command and its arguments") {
		t.Fatalf("no Check row in the fixture:\n%s", withChecks)
	}
	without := run(sarif.Result{RuleID: "python.lang.security.audit.eval-detected.eval-detected", Level: sarif.LevelError,
		Priority: "P2", Tool: "semgrep", Location: sarif.Location{URI: "app/x.py", StartLine: 3}})
	if strings.Contains(without, checkEnding) {
		t.Errorf("a run with no Check row says how one ends:\n%s", without)
	}
}
