package report

import (
	"strings"
	"testing"
)

var twoPublished = []PublishedRun{
	{Server: "https://api.draugr.example", Project: "payments", Run: "run-7",
		URL: "https://console.draugr.example/#/projects/payments/runs/run-7"},
	{Server: "https://draugr.internal.example", Project: "payments", Run: "run-3", Duplicate: true},
}

// publishedBlock is the console's PUBLISHED block, its heading and rows, with the spacing between
// columns closed up, or empty where it printed none.
func publishedBlock(out string) []string {
	var rows []string
	in := false
	for line := range strings.SplitSeq(out, "\n") {
		switch {
		case strings.TrimSpace(line) == "PUBLISHED" || strings.TrimSpace(line) == "Published":
			in = true
		case in && strings.TrimSpace(line) == "":
			return rows
		case in:
			rows = append(rows, strings.Join(strings.Fields(line), " "))
		}
	}
	return rows
}

// Each run a server recorded is named after the reports, by its page where the server gave one and
// by its id and server where it did not, in every view.
func TestTheConsoleNamesWhereTheRunWasPublished(t *testing.T) {
	want := []string{
		"https://console.draugr.example/#/projects/payments/runs/run-7 payments · run-7",
		"run-3 payments · https://draugr.internal.example · recorded by an earlier attempt",
	}
	for _, view := range []View{ViewFindings, ViewCompact, ViewActions} {
		d := Data{Published: twoPublished, View: view}
		got := publishedBlock(renderConsole(t, d))
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("view %v: PUBLISHED =\n%s\nwant\n%s", view, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	if got := publishedBlock(renderConsole(t, Data{})); got != nil {
		t.Errorf("a run published nowhere prints %q", got)
	}
}

// The change view ends on the same tail, so a pull request's run names where it went too.
func TestTheChangeViewNamesWhereTheRunWasPublished(t *testing.T) {
	d := judged(GateSettings{})
	d.Published = twoPublished[:1]
	got := publishedBlock(renderConsole(t, d))
	if len(got) != 1 || !strings.HasPrefix(got[0], twoPublished[0].URL) {
		t.Errorf("PUBLISHED = %q", got)
	}
}

// The HTML report says it at its foot, linking the page where there is one.
func TestTheHTMLReportNamesWhereTheRunWasPublished(t *testing.T) {
	out := renderHTML(t, Data{Published: twoPublished})
	for _, want := range []string{
		`Published to https://api.draugr.example as <a href="https://console.draugr.example/#/projects/payments/runs/run-7">run run-7</a> in payments.`,
		`Published to https://draugr.internal.example as run <code>run-3</code> in payments. The server had already recorded this run from an earlier attempt.`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(renderHTML(t, Data{}), "Published to") {
		t.Error("a run published nowhere says it was published")
	}
}
