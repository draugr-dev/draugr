package report

import (
	"strings"
	"testing"
)

// The FOUND section is in the console, the HTML report and the markdown report, after the controls
// in each, with every row the caller passed and the note saying where the rows came from.
func TestFoundIsInEveryReportAfterTheControls(t *testing.T) {
	d := goldenZeroConfigData()

	console := renderWith(t, consoleReporter{}, d)
	if !strings.Contains(console, "FOUND  "+foundNote+"\n") {
		t.Errorf("the console has no FOUND heading:\n%s", console)
	}
	if !before(console, "CONTROLS", "FOUND") || !before(console, "FOUND", "CAVEATS") {
		t.Errorf("FOUND does not sit between CONTROLS and CAVEATS:\n%s", console)
	}

	doc := renderHTML(t, d)
	html := section(t, doc, `<summary id="found">`, `</details>`)
	md := renderWith(t, markdownReporter{}, d)
	mdFound := section(t, md, "### Found", "\n### ")
	for _, f := range d.Found {
		if want := "<tr><td>" + f.Kind + "</td><td><code>" + f.Files + "</code></td><td>" + f.Did + "</td></tr>"; !strings.Contains(html, want) {
			t.Errorf("the HTML report has no row %s:\n%s", want, html)
		}
		if want := "| " + f.Kind + " | " + f.Files + " | " + f.Did + " |\n"; !strings.Contains(mdFound, want) {
			t.Errorf("the markdown report has no row %q:\n%s", want, mdFound)
		}
	}
	if !strings.Contains(html, "<code>draugr init</code> writes to\n<code>draugr.saga.yaml</code>") {
		t.Errorf("the HTML note does not say where the rows go:\n%s", html)
	}
	if !strings.Contains(mdFound, "\nWhat the run read from the tree, which `draugr init` writes to `draugr.saga.yaml`.\n") {
		t.Errorf("the markdown note does not say where the rows go:\n%s", mdFound)
	}
	if !before(doc, `href="#controls"`, `href="#found"`) || !before(doc, `<summary id="controls">`, `<summary id="found">`) {
		t.Error("the HTML report's Found does not follow Controls")
	}
	if !before(md, "### Controls", "### Found") || !before(md, "### Found", "### Caveats") {
		t.Errorf("the markdown report's Found is not between Controls and Caveats:\n%s", md)
	}
}

// A run from a descriptor passes no rows and gets no section, in any format. The compact view
// leaves it out too, as it leaves out the other blocks that describe the run.
func TestARunWithNothingFoundHasNoFoundSection(t *testing.T) {
	d := goldenZeroConfigData()
	d.Found = nil
	if got := renderWith(t, consoleReporter{}, d); strings.Contains(got, "FOUND") {
		t.Errorf("the console has a FOUND section with nothing found:\n%s", got)
	}
	if got := renderHTML(t, d); strings.Contains(got, `id="found"`) || strings.Contains(got, `href="#found"`) {
		t.Error("the HTML report has a Found section with nothing found")
	}
	if got := renderWith(t, markdownReporter{}, d); strings.Contains(got, "### Found") {
		t.Errorf("the markdown report has a Found section with nothing found:\n%s", got)
	}

	compact := goldenZeroConfigData()
	compact.View = ViewCompact
	if got := renderWith(t, consoleReporter{}, compact); strings.Contains(got, "FOUND") ||
		!strings.Contains(got, "govulncheck needs Go") {
		t.Errorf("the compact view keeps FOUND or drops a caveat:\n%s", got)
	}
}

// before reports whether a occurs in doc, and before b.
func before(doc, a, b string) bool {
	i := strings.Index(doc, a)
	return i >= 0 && i < strings.Index(doc, b)
}
