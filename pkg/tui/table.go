package tui

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Cell is one value in a table row: the text, how it should read, and optionally where it
// points. The zero value is a plain, unlinked cell, so a caller only names what differs.
type Cell struct {
	Text  string
	Style Style
	// URL turns the cell into a hyperlink where the terminal supports it. It costs no width,
	// which is what makes it usable in a table that's already wide.
	URL string
	// Note is a second part of the same cell, set after Text in its own style and separated by a
	// space. It is measured, so the column still lines up.
	//
	// For a qualifier that belongs to a value rather than beside it. A column of two-character
	// values under an eight-character heading wastes six columns on every row, and a qualifier
	// given a column of its own pays for the heading twice.
	Note      string
	NoteStyle Style
}

// PlainCell is a cell that's just text.
func PlainCell(text string) Cell { return Cell{Text: text} }

// Styled is a cell that reads as the given role.
func Styled(style Style, text string) Cell { return Cell{Text: text, Style: style} }

// cellWidth is what a cell occupies on screen, both parts of it.
func cellWidth(c Cell) int {
	if c.Note == "" {
		return width(c.Text)
	}
	return width(c.Text) + 1 + width(c.Note)
}

type row struct {
	cells []Cell
	// notes are supporting lines printed under the row, indented past the first column and
	// dimmed. It's how a table says more than its columns have room for.
	notes []string
}

// Table renders aligned columns for a person reading a terminal.
//
// It exists because alignment and color interact badly: any padding computed after styling
// counts escape bytes as visible width and the columns drift apart. text/tabwriter has the same
// flaw, its Escape mechanism hides the bytes from parsing but still measures them, so every
// command that wanted color was going to hand-roll its own width arithmetic. Table measures the
// plain text, pads, and only then paints.
type Table struct {
	painter Painter
	indent  string
	headers []string
	rows    []row
	// styledNotes says the caller paints its own continuation lines, for a note where one part of
	// the sentence is the part to read.
	styledNotes bool
	// fit is how wide the table may be, or zero for as wide as its content.
	fit int
}

// Fit bounds the table's width, trimming the last column's text to what is left after the others.
//
// The last column because it is the only one nothing follows, and because a table is bounded by a
// terminal rather than by a design: the columns before it are identifiers and locations, which are
// useless shortened, and the last one is prose, which is readable shortened and still readable
// gone. A width of zero leaves the table as wide as its content, which is the right answer when
// the destination is a file or a pipe and there is no width to respect.
func (t *Table) Fit(width int) *Table {
	t.fit = width
	return t
}

// StyledNotes tells the table its notes arrive painted, so it sets them as given rather than
// dimming them whole.
func (t *Table) StyledNotes() *Table {
	t.styledNotes = true
	return t
}

// NewTable starts a table written with p. Headers may be omitted for a table whose columns
// need no labeling; when given, they're dimmed so they frame the data without competing.
func NewTable(p Painter, headers ...string) *Table {
	return &Table{painter: p, headers: headers}
}

// Indent sets a prefix for every line, for tables nested under a heading.
func (t *Table) Indent(prefix string) *Table {
	t.indent = prefix
	return t
}

// Row appends a row. Rows may be shorter than the header, missing cells render empty.
func (t *Table) Row(cells ...Cell) *Table {
	t.rows = append(t.rows, row{cells: cells})
	return t
}

// RowWithNote appends a row followed by a dimmed continuation line, aligned under the second
// column. Use it when a row's own columns can't carry the explanation.
func (t *Table) RowWithNote(note string, cells ...Cell) *Table {
	return t.RowWithNotes([]string{note}, cells...)
}

// RowWithNotes appends a row followed by several dimmed continuation lines, each aligned under
// the second column. Empty strings are dropped, so a caller can pass a line that may or may not
// have anything to say without guarding at the call site.
func (t *Table) RowWithNotes(notes []string, cells ...Cell) *Table {
	kept := make([]string, 0, len(notes))
	for _, n := range notes {
		if n != "" {
			kept = append(kept, n)
		}
	}
	t.rows = append(t.rows, row{cells: cells, notes: kept})
	return t
}

// Render writes the table. Columns are sized to their widest plain-text value, and the final
// column is never padded. Nothing follows it, and trailing spaces are noise in a diff or a
// copied-out log.
func (t *Table) Render(w io.Writer) {
	cols := len(t.headers)
	for _, r := range t.rows {
		if len(r.cells) > cols {
			cols = len(r.cells)
		}
	}
	if cols == 0 {
		return
	}

	widths := make([]int, cols)
	for i, h := range t.headers {
		widths[i] = width(h)
	}
	for _, r := range t.rows {
		for i, c := range r.cells {
			if n := cellWidth(c); n > widths[i] {
				widths[i] = n
			}
		}
	}

	widths = widths[:t.trimToFit(widths)]

	if len(t.headers) > 0 {
		cells := make([]Cell, min(len(t.headers), len(widths)))
		for i := range cells {
			cells[i] = Styled(StyleMuted, t.headers[i])
		}
		t.writeLine(w, widths, cells)
	}
	for _, r := range t.rows {
		t.writeLine(w, widths, r.cells)
		// Align notes under the second column: far enough in to read as subordinate to the
		// row, not as rows of their own.
		//
		// Capped, because the first column can carry a qualifier and grow. A note is usually the
		// longest text in the table, and an indent that tracks a wide first column pushes the end
		// of it off an ordinary terminal to keep an alignment nobody is checking.
		pad := strings.Repeat(" ", min(widths[0], noteIndent)+columnGap)
		for _, n := range r.notes {
			if !t.styledNotes {
				n = t.painter.Paint(StyleMuted, n)
			}
			_, _ = fmt.Fprintf(w, "%s%s%s\n", t.indent, pad, n)
		}
	}
}

// noteIndent is how far a continuation line may be pushed in before the alignment costs more
// than it is worth.
const noteIndent = 10

// trimToFit shortens the last column so the whole row fits, and returns how many columns are left.
//
// Below minLastColumn there is no sentence worth reading, so the column goes entirely rather than
// leaving a ragged edge of first words.
func (t *Table) trimToFit(widths []int) int {
	last := len(widths) - 1
	if t.fit <= 0 || last < 1 {
		return len(widths)
	}
	used := width(t.indent) + last*columnGap
	for _, w := range widths[:last] {
		used += w
	}
	room := t.fit - used
	if room >= widths[last] {
		return len(widths)
	}
	if room < minLastColumn {
		return last
	}
	widths[last] = room
	for _, r := range t.rows {
		if last < len(r.cells) {
			r.cells[last].Text = clip(r.cells[last].Text, room)
		}
	}
	if last < len(t.headers) {
		t.headers[last] = clip(t.headers[last], room)
	}
	return len(widths)
}

// minLastColumn is the narrowest a trimmed column may be before it says nothing worth the space.
const minLastColumn = 24

// clip shortens s to n cells, marking that it was cut. Cutting at a space where one is near the
// edge: a fragment of a word reads as a different word, and a reader cannot tell which they have.
func clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := n - 1
	if space := strings.LastIndex(string(r[:cut]), " "); space > n/2 {
		cut = len([]rune(string(r[:cut])[:space]))
	}
	return strings.TrimRight(string(r[:cut]), " ") + "…"
}

// columnGap is the space between columns. Two is enough to separate them and tight enough that
// a wide table still fits.
const columnGap = 2

func (t *Table) writeLine(w io.Writer, widths []int, cells []Cell) {
	var b strings.Builder
	b.WriteString(t.indent)
	for i := range widths {
		var c Cell
		if i < len(cells) {
			c = cells[i]
		}
		text := c.Text
		last := i == len(widths)-1
		painted := t.painter.Link(c.URL, t.painter.Paint(c.Style, text))
		if c.Note != "" {
			painted += " " + t.painter.Paint(c.NoteStyle, c.Note)
		}
		if !last {
			// Pad after painting, measured on the text: escape codes have no width on screen but
			// plenty in a string.
			painted += strings.Repeat(" ", widths[i]-cellWidth(c))
		}
		b.WriteString(painted)
		if !last {
			b.WriteString(strings.Repeat(" ", columnGap))
		}
	}
	// A row whose trailing cells were empty leaves padding behind; nothing follows it.
	_, _ = fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
}

// width is a cell's display width. Counting runes rather than bytes is what makes the ✓ and ✗
// in a status column line up. It still assumes one column per rune, which is wrong for
// double-width scripts, a real problem, but not one Draugr's output has today.
func width(s string) int { return utf8.RuneCountInString(s) }
