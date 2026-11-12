package report

import (
	"slices"
	"strings"
	"testing"
)

// A run that wrote reports names each file under REPORTS, as a whole path, the HTML report first.
// A run that wrote none has no REPORTS block, so it cannot be read as one that did.
func TestARunNamesTheReportsItWrote(t *testing.T) {
	out := renderConsole(t, withReports(goldenFullData(), ".draugr/out", "json", "sarif", "html"))
	_, block, ok := strings.Cut(out, "\nREPORTS\n")
	if !ok {
		t.Fatalf("no REPORTS block:\n%s", out)
	}
	var paths []string
	for _, l := range strings.Split(block, "\n") {
		if !strings.HasPrefix(l, "  ") {
			break
		}
		paths = append(paths, strings.Fields(l)[0])
	}
	want := []string{".draugr/out/report.html", ".draugr/out/results.sarif", ".draugr/out/report.json"}
	if !slices.Equal(paths, want) {
		t.Errorf("REPORTS = %q, want %q", paths, want)
	}
	if strings.Contains(out, reportRowSays) {
		t.Errorf("a run that wrote the HTML report is offered it again:\n%s", out)
	}
	if none := renderConsole(t, goldenFullData()); strings.Contains(none, "\nREPORTS\n") {
		t.Errorf("a run that wrote nothing has a REPORTS block:\n%s", none)
	}
}

// --top 0 lists every finding, which is the volume the HTML report is for, so it is offered there too.
func TestTopZeroIsOfferedTheHTMLReport(t *testing.T) {
	d := goldenFullData()
	d.TopN = -1
	if rows := tryRows(renderConsole(t, d)); !slices.Contains(rows, "--report json,sarif,html -o .draugr/out "+reportRowSays) {
		t.Errorf("TRY = %q, want the HTML report offered", rows)
	}
}

// A format other than the three named first keeps its place after them.
func TestShownFormatsPutTheHTMLReportFirst(t *testing.T) {
	got := shownFormats(Data{Reports: []string{"markdown", "json", "html", "junit"}})
	if want := []string{"html", "json", "markdown", "junit"}; !slices.Equal(got, want) {
		t.Errorf("shownFormats = %q, want %q", got, want)
	}
	for dir, want := range map[string]bool{".draugr/out": true, "./.draugr/out/": true, ".": true, "draugr-out": true, "out": false} {
		if got := explainFinds(dir); got != want {
			t.Errorf("explainFinds(%q) = %v, want %v", dir, got, want)
		}
	}
}
