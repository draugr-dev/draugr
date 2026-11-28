package report

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// endWriter passes writes through and remembers how the output so far ends, so the closer is set
// off from whatever came before it by exactly one blank line. It answers tui.Columns for the
// writer it wraps, so nothing drawn through it loses the terminal's width.
type endWriter struct {
	w    io.Writer
	last string // the last two bytes written, or fewer
}

func (e *endWriter) Write(p []byte) (int, error) {
	n, err := e.w.Write(p)
	e.last += string(p[max(0, n-2):n])
	if len(e.last) > 2 {
		e.last = e.last[len(e.last)-2:]
	}
	return n, err
}

// Columns is the width of the writer underneath.
func (e *endWriter) Columns() int { return tui.Columns(e.w) }

// writeCloser ends a run on its answer, the last thing in the window when the scroll stops.
//
// The verdict line at the top has scrolled away by the time a long run finishes, and what is left
// on screen is the TRY rows. So the run ends where the reader's eye already is: the verdict and
// the counts, what failed the run, and the one finding to start on.
//
// first is the first FIX FIRST row, or nil where the run listed none.
func writeCloser(e *endWriter, col tui.Painter, s summary, d Data, first *finding, blobs blobLinker) {
	switch {
	case e.last == "":
	case !strings.HasSuffix(e.last, "\n"):
		_, _ = fmt.Fprint(e, "\n\n")
	case e.last != "\n\n":
		_, _ = fmt.Fprintln(e)
	}

	verdict, vcol := "PASS", cPass
	if s.verdict == norn.Fail {
		verdict, vcol = "FAIL", cFail
	}
	line := col.Paint(cDim, "DRAUGR") + "  " + col.Chip(vcol, verdict) + "  "
	switch {
	case len(s.findings) == 0:
		line += "no findings"
	case s.prioritized:
		line += strings.TrimSpace(bandChips(col, s))
	default:
		line += english.Count(len(s.findings), "finding")
	}
	// A scoped or partial run says so here too: a PASS read on its own as the last line would
	// otherwise cover more than the run did.
	for _, n := range coverageNotes(d) {
		line += col.Paint(cAccent, " · "+strings.ToLower(n[:1])+strings.TrimSuffix(n[1:], "."))
	}
	_, _ = fmt.Fprintln(e, line)

	if why := closerWhy(s, d); why != "" {
		_, _ = fmt.Fprintf(e, "  %s\n", col.Paint(cDim, why))
	}
	if first != nil {
		writeCloserFix(e, col, *first, blobs)
	}
}

// closerWhy names what fails the run: the controls that found something past the gate, the ones a
// scan error left incomplete, and the caveats the gate fails on. Empty for a run nothing fails.
func closerWhy(s summary, d Data) string {
	var failed, errored []string
	for _, c := range d.Verdict.Controls {
		switch {
		case d.Run.Incomplete(c.Control):
			errored = append(errored, c.Control)
		case c.Verdict == norn.Fail:
			failed = append(failed, c.Control)
		}
	}
	// The controls that produced no report at all, which have no verdict entry above.
	errored = append(errored, s.errored...)
	var parts []string
	if len(failed) > 0 {
		parts = append(parts, english.And(failed)+" "+english.Choose(len(failed), "fails", "fail"))
	}
	if len(errored) > 0 {
		parts = append(parts, english.And(errored)+" errored")
	}
	if failing, _ := splitCaveats(d); len(failing) > 0 {
		parts = append(parts, english.Count(len(failing), "caveat")+" "+english.Choose(len(failing), "fails", "fail")+" the run")
	}
	return strings.Join(parts, " · ")
}

// writeCloserFix is the closer's third line: the first FIX FIRST row, its rule, its fix in the row's
// own words, and where it is.
//
// Within messageWidth or the terminal, and nothing on it is cut: the rule id and the location are
// what a reader copies into config.exclude, which matches them only whole. Where the line does not
// fit, the location goes on a line of its own under the rule, and where the rule and the fix still
// do not fit, the fix goes there too, before the location.
func writeCloserFix(w io.Writer, col tui.Painter, f finding, blobs blobLinker) {
	fixPlain, fixPainted := closerFix(col, f)
	where := labeledWhere(f, whereShown(displayLocation(f)))
	linked := col.Paint(cDim, col.Link(blobs.forFinding(f), where))
	dot := " " + col.Paint(cDim, "·") + " "

	room := messageWidth
	if c := tui.Columns(w); c > 0 {
		room = min(room, c)
	}
	const label = "  FIX FIRST  "
	fits := func(s string) bool { return utf8.RuneCountInString(label+s) <= room }
	rule := "  " + heading(col, "Fix first") + "  " + col.Paint(tui.StyleStrong, f.ruleID)
	under := strings.Repeat(" ", len(label))
	switch {
	case fits(f.ruleID + " · " + fixPlain + " · " + where):
		_, _ = fmt.Fprintln(w, rule+dot+fixPainted+dot+linked)
	case fits(f.ruleID + " · " + fixPlain):
		_, _ = fmt.Fprintln(w, rule+dot+fixPainted)
		_, _ = fmt.Fprintln(w, under+linked)
	default:
		_, _ = fmt.Fprintln(w, rule)
		_, _ = fmt.Fprintln(w, under+fixPainted+dot+linked)
	}
}

// closerFix is a finding's fix as its FIX FIRST row says it, plain for measuring and painted for
// printing: the image to move to, the package and the release to move to, or the package and the
// phrase that says what to do.
func closerFix(col tui.Painter, f finding) (plain, painted string) {
	name, fixed := packageFix(f, true)
	join := func(a, b string) string { return strings.TrimSpace(a + " " + b) }
	if u := imageUpdate(f); u != "" {
		return join(name, "fix "+u), join(name, col.Paint(cDim, "fix")+" "+col.Paint(tui.StyleFixed, u))
	}
	if fixed != "" {
		return name + " → " + fixed, name + " " + col.Paint(tui.StyleFixed, "→ "+fixed)
	}
	phrase := fixPhrase(f)
	return join(name, "fix "+phrase), join(name, col.Paint(cDim, "fix")+" "+col.Paint(tui.StyleFixed, phrase))
}
