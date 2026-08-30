package report

import (
	"fmt"
	"io"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// evidenceReporter renders what makes a run defensible, as a document.
//
// The same content as `--evidence` on the console, delivered the other way: one is for somebody
// reading it now, the other for somebody attaching it to a review or keeping it beside a release.
// Rendered from the same function so the two cannot drift into disagreeing about what a run did.
//
// A companion rather than a replacement. It answers "can I trust this run", not "what did it
// find" — duplicating hundreds of findings into it would make it unreadable for its own purpose,
// and they are already in the report and the SARIF beside it.
type evidenceReporter struct{}

func (evidenceReporter) Format() string { return "evidence" }

func (evidenceReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)
	col := tui.For(w)

	_, _ = fmt.Fprintf(w, "Draugr evidence — %s", releaseLabel(d))
	if !d.Generated.IsZero() {
		_, _ = fmt.Fprintf(w, "\nGenerated %s by Draugr %s",
			d.Generated.UTC().Format("2006-01-02 15:04:05 UTC"), d.Version)
	}
	_, _ = fmt.Fprint(w, "\n\n")

	writeEvidence(w, col, d, s)

	// The verdict last, because this document exists to say what stands behind it. A reader who
	// wanted only the verdict has it in every other format.
	_, _ = fmt.Fprintf(w, "Verdict: %s\n", d.Verdict.Verdict)
	return nil
}

// releaseLabel names what was scanned, or says plainly that the descriptor did not.
func releaseLabel(d Data) string {
	name := d.ProjectName()
	if name == "" {
		return "unnamed release"
	}
	if d.Release.Version == "" {
		return name
	}
	return name + " " + d.Release.Version
}
