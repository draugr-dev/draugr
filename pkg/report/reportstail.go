package report

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// defaultReportsDir is where the console suggests a run write its reports: the first place
// `draugr explain` looks, so the run it suggests is one explain can read.
var defaultReportsDir = filepath.Join(".draugr", "out")

// suggestedReports are the formats a suggested run writes: the HTML report to read, and the SARIF and
// JSON that `draugr explain`, `--base` and `draugr diff` read. --report replaces the default list
// rather than adding to it, so a suggestion naming html alone writes a run nothing else can use.
var suggestedReports = []string{"json", "sarif", "html"}

// reportRowSays is what the TRY row suggesting the HTML report says it gives.
const reportRowSays = "every finding in one searchable page"

// wroteHTML reports whether this run writes the HTML report.
func wroteHTML(d Data) bool { return d.ReportsDir != "" && slices.Contains(d.Reports, "html") }

// wantsReport reports whether the console should point to the HTML report: the run writes none, and
// the console either cut a block short (findings, caveats or targets not reached) or listed every
// finding with --top 0, which is the volume the report is for.
func wantsReport(s summary, d Data, listed int) bool {
	return !wroteHTML(d) && (cutShort(d, listed) || d.TopN < 0 && len(s.findings) > 0)
}

// reportPurpose says what each written file is for, in the words a reader choosing one needs.
var reportPurpose = map[string]string{
	"html":  "every finding, searchable and filtered by component",
	"sarif": "what draugr explain, --base and draugr diff read",
	"json":  "the whole run, for a script",
}

// shownFormats are the formats a run wrote, the HTML report first because it is the one a person
// opens, then the files other commands read, then the rest in the order they were given.
func shownFormats(d Data) []string {
	out := make([]string, 0, len(d.Reports))
	for _, f := range []string{"html", "sarif", "json"} {
		if slices.Contains(d.Reports, f) {
			out = append(out, f)
		}
	}
	for _, f := range d.Reports {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// writeReports is the REPORTS block: each file the run wrote, as a whole path a terminal can open,
// and what it is for. Nothing where the run wrote none; the TRY block says how to write them.
//
// Apart from TRY, so a run that wrote nothing cannot be read as one that did: the command to run sits
// among the other things to try, and the files that exist sit under their own heading.
func writeReports(w io.Writer, col tui.Painter, d Data) {
	if d.ReportsDir == "" || len(d.Reports) == 0 {
		return
	}
	t := tui.NewTable(col).Indent("  ")
	for _, f := range shownFormats(d) {
		t.Row(tui.Styled("", filepath.Join(d.ReportsDir, Filename(f))), tui.Styled(cDim, reportPurpose[f]))
	}
	_, _ = fmt.Fprintln(w, heading(col, "Reports"))
	t.Render(w)
	_, _ = fmt.Fprintln(w)
}

// explainFinds reports whether `draugr explain` finds a run's SARIF in dir without being told, the
// directories it looks in when given no -r.
func explainFinds(dir string) bool {
	switch filepath.Clean(dir) {
	case defaultReportsDir, ".", "draugr-out", ".draugr-out":
		return true
	}
	return false
}
