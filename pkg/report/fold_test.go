package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

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
	line := func(path string) action { return lineAction("P1", "api", "r", path, "Handle the returned error") }
	rule := action{key: "iac\x00x", title: "Fix x"}
	for _, c := range []struct {
		name string
		as   []action
		want string
	}{
		{"folded", []action{line("a.go:1"), line("a.go:2")}, "1 action on 2 lines"},
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
	if !strings.Contains(out, "2 lines · 2 findings · a.go:1,2") {
		t.Errorf("want the lines named:\n%s", out)
	}
	if strings.Contains(out, "control sast") {
		t.Errorf("one control's rows should not repeat it:\n%s", out)
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
