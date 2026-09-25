package report

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// A finding is drawn as a block of three lines rather than as a row of columns.
//
// A table sizes every column to its widest value, and the values here have no common size: a rule
// id is short, a component name is whatever somebody called it, and a location is anything from
// `go.mod:12` to an image reference carrying a 71-character digest. One image therefore set the
// width of a column that 984 other findings paid for, and the table came out at 217 columns on a
// 120-column terminal, where a terminal wraps every row and the listing stops being one.
//
// The bound cannot be recovered by trimming, either: `Table.Fit` shortens the last column, and the
// columns before it had already spent the budget. What a reader loses is whichever column happened
// to be last, which is the one saying what to do about the finding.
//
// So there are no columns beyond the two that are fixed width anyway. Nothing here can be widened
// by one long value, at any terminal size.
const (
	// blockGutter is where the first line's text starts, after the band and the severity.
	blockGutter = 16
	// blockIndent is where the two lines under it start. Short of the gutter, so the band and the
	// severity keep an edge of their own and a reader can see where one finding ends.
	blockIndent = 6
	// narrowestBlock is the width assumed where there is none to read: a file, or a pipe. The
	// sentences are bounded by messageWidth regardless, so this only decides how much of a long
	// location survives.
	narrowestBlock = messageWidth + blockGutter
)

// renderFixFirstBlocks prints each ranked finding as a block: what it is, what is known about it,
// and where it is.
func renderFixFirstBlocks(w io.Writer, col tui.Painter, fs []finding, shared bool, blobs blobLinker) {
	width := tui.Columns(w)
	if width <= 0 {
		width = narrowestBlock
	}
	// The same question the columns asked, for the same reason: a value identical on every finding
	// distinguishes none of them, and the release header already said what was scanned.
	withComponent := manyComponents(fs, shared)
	withRepository := manyRepositories(fs)

	for i, f := range fs {
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		writeBlockHead(w, col, f, width)
		writeBlockFacts(w, col, f, width, withComponent, withRepository)
		writeBlockWhere(w, col, f, width, blobs)
	}
}

// writeBlockHead is the first line: the band, the severity, and what the finding says.
func writeBlockHead(w io.Writer, col tui.Painter, f finding, width int) {
	priority := dash(f.priority)
	severity := string(rankedSeverity(f))
	line := "  " +
		padPainted(col.Paint(priorityColor(f.priority), priority), priority, 4) +
		padPainted(col.Paint(severityColor(rankedSeverity(f)), severity), severity, 10)

	// The rule id links to what it means, which costs no width. A rule id names a finding; it does
	// not explain it.
	rule := shortRuleID(f.ruleID)
	line += col.Link(f.helpURI, rule)
	if title := findingTitle(f); title != "" {
		room := width - blockGutter - utf8.RuneCountInString(rule) - len(" · ")
		if room > 0 {
			line += col.Paint(cDim, " · ") + elide(title, min(room, messageWidth))
		}
	}
	_, _ = fmt.Fprintln(w, line)
}

// writeBlockFacts is the second line: what moved the band, and what is known about the finding.
//
// The mark leads it. It qualifies everything after it, and a reader who has just read what the
// finding says meets the argument against its band before the facts that follow from it.
func writeBlockFacts(w io.Writer, col tui.Painter, f finding, width int, withComponent, withRepository bool) {
	var parts []string
	if m := movedBy(f); m != nil {
		parts = append(parts, col.Paint(m.style, m.glyph+" "+m.label))
	}
	label := func(name, value string) string {
		return col.Paint(cDim, name) + " " + value
	}
	if withComponent {
		c := f.component
		if c == "" {
			c = "none"
		}
		parts = append(parts, label("component", c))
	}
	if withRepository && f.repository != "" {
		parts = append(parts, label("repository", shortRepository(f.repository)))
	}
	if f.tool != "" {
		// Lowercased, because half these names are what the tool calls itself and half are what
		// Draugr runs it as, and one scanner under two spellings reads as two scanners.
		parts = append(parts, label("scanner", strings.ToLower(f.tool)))
	}
	// Always, and as a phrase. A version is the answer for a vulnerable dependency and there is no
	// version to give for a misconfiguration, a hardcoded secret, or a flaw in the code itself,
	// which between them are most of what a scan finds.
	parts = append(parts, col.Paint(cDim, "fix")+" "+col.Paint(tui.StyleFixed, fixPhrase(f)))

	_, _ = fmt.Fprintln(w, blockLine(col, parts, width))
}

// writeBlockWhere is the third line: where the finding is, and anything standing behind it.
func writeBlockWhere(w io.Writer, col tui.Painter, f finding, width int, blobs blobLinker) {
	where := dash(displayLocation(f))
	linked := col.Paint(cDim, col.Link(blobs.forFinding(f), where))

	// The working behind the mark on the line above: which analyzer, which floor, what else found
	// it, and for a secret already published, that deleting it is not remediation.
	said := reasoning(col, f)
	if len(said) == 0 {
		_, _ = fmt.Fprintln(w, blockLine(col, []string{linked}, width))
		return
	}
	plain, painted := make([]string, 0, len(said)), make([]string, 0, len(said))
	for _, p := range said {
		plain = append(plain, p.plain)
		painted = append(painted, p.painted)
	}
	joined := strings.Join(plain, " · ")

	// Beside the location where it fits, and on a line of its own where it does not. Never
	// dropped: these are the sentences saying the band was argued with and what to do instead, so
	// a finding that loses them reads as one nobody questioned.
	if blockIndent+utf8.RuneCountInString(where)+len(" · ")+utf8.RuneCountInString(joined) <= width {
		_, _ = fmt.Fprintln(w, blockLine(col, append([]string{linked}, painted...), width))
		return
	}
	_, _ = fmt.Fprintln(w, blockLine(col, []string{linked}, width))
	_, _ = fmt.Fprintln(w, blockLine(col, []string{elideParts(col, said, min(width-blockIndent, messageWidth))}, width))
}

// elideParts renders the working to a width, cutting the last part rather than dropping any.
func elideParts(col tui.Painter, parts []notePart, width int) string {
	painted := make([]string, 0, len(parts))
	room := width
	for i, p := range parts {
		if i > 0 {
			room -= len(" · ")
		}
		if room <= 0 {
			break
		}
		painted = append(painted, col.Paint(cDim, elide(p.plain, room)))
		room -= utf8.RuneCountInString(p.plain)
	}
	return strings.Join(painted, col.Paint(cDim, " · "))
}

// blockLine joins one of the lines under the head, indented and separated the way every other
// list of facts Draugr prints is.
func blockLine(col tui.Painter, parts []string, _ int) string {
	return strings.Repeat(" ", blockIndent) + strings.Join(parts, col.Paint(cDim, " · "))
}

// padPainted pads painted text by what a reader sees rather than by the bytes the escapes add.
func padPainted(painted, plain string, width int) string {
	if n := width - utf8.RuneCountInString(plain); n > 0 {
		return painted + strings.Repeat(" ", n)
	}
	return painted + " "
}
