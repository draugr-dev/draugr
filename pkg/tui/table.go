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
	// Shorten, where set, is the cell's text cut to at most the given number of cells, for a table
	// bounded by Fit whose rows are wider than the bound. A list keeps its first items and counts the
	// rest, which a cut made at the edge cannot do.
	Shorten func(width int) string
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
	// moveLast says a row too wide to sit beside the others puts its last cell on a line of its
	// own, rather than every row's last cell being cut to make room for it.
	moveLast bool
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

// MoveLast tells a table bounded by Fit to move the last cell of a row whose leading cells are too
// wide onto a line of its own, under the last column, instead of cutting it.
//
// For a table whose last column is a sentence a reader needs whole, such as what a command does.
// Without it, one long command widens the first column for every row, and every description is
// cut to what is left. A row moves only while the rest would otherwise not fit, widest first.
func (t *Table) MoveLast() *Table {
	t.moveLast = true
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

	t.shorten(cols)
	moved := t.moveRows(cols)
	widths := t.widths(cols, moved)
	// Where a moved row's last cell starts: under the last column, as the leading columns set it
	// before the last one is trimmed.
	start := width(t.indent) + (cols-1)*columnGap
	for _, n := range widths[:cols-1] {
		start += n
	}
	widths = widths[:t.trimToFit(widths, moved)]

	if len(t.headers) > 0 {
		cells := make([]Cell, min(len(t.headers), len(widths)))
		for i := range cells {
			cells[i] = Styled(StyleMuted, t.headers[i])
		}
		t.writeLine(w, widths, cells)
	}
	for i, r := range t.rows {
		if moved[i] {
			t.writeMoved(w, widths, r.cells, start)
		} else {
			t.writeLine(w, widths, r.cells)
		}
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

// widths are the columns' widths: the widest header or cell in each, leaving out the rows moved,
// which are written on lines of their own.
func (t *Table) widths(cols int, moved map[int]bool) []int {
	widths := make([]int, cols)
	for i, h := range t.headers {
		widths[i] = width(h)
	}
	for j, r := range t.rows {
		if moved[j] {
			continue
		}
		for i, c := range r.cells {
			widths[i] = max(widths[i], cellWidth(c))
		}
	}
	return widths
}

// fits reports whether a row of these widths is no wider than the table's bound.
func (t *Table) fits(widths []int) bool {
	used := width(t.indent) + (len(widths)-1)*columnGap
	for _, n := range widths {
		used += n
	}
	return used <= t.fit
}

// shorten cuts the cells that offer a shorter form, column by column from the left, to what the
// bound leaves beside every other column at its full width, and no narrower than minLastColumn.
func (t *Table) shorten(cols int) {
	if t.fit <= 0 {
		return
	}
	for c := range cols - 1 {
		widths := t.widths(cols, nil)
		if t.fits(widths) {
			return
		}
		room := t.fit - width(t.indent) - (cols-1)*columnGap
		for i, n := range widths {
			if i != c {
				room -= n
			}
		}
		room = max(room, minLastColumn)
		for _, r := range t.rows {
			if c < len(r.cells) && r.cells[c].Shorten != nil && cellWidth(r.cells[c]) > room {
				r.cells[c].Text = r.cells[c].Shorten(room)
			}
		}
	}
}

// moveRows picks the rows whose last cell goes on a line of its own, under MoveLast: while the rows
// left do not fit, the one whose leading cells are widest, where moving it narrows those columns.
func (t *Table) moveRows(cols int) map[int]bool {
	moved := map[int]bool{}
	if !t.moveLast || t.fit <= 0 || cols < 2 {
		return moved
	}
	lead := func(r row) int {
		n := 0
		for i, c := range r.cells[:min(len(r.cells), cols-1)] {
			if i > 0 {
				n += columnGap
			}
			n += cellWidth(c)
		}
		return n
	}
	for {
		widths := t.widths(cols, moved)
		if t.fits(widths) {
			return moved
		}
		widest, most, next := -1, 0, 0
		for j, r := range t.rows {
			if moved[j] {
				continue
			}
			n := lead(r)
			if len(r.cells) < cols || r.cells[cols-1].Text == "" || n <= most {
				// A row with nothing in the last column stays, and still holds the columns open.
				next = max(next, n)
				continue
			}
			next = max(next, most)
			widest, most = j, n
		}
		// Moving the widest row helps only where it alone sets the leading columns' width.
		if widest < 0 || most <= next {
			return moved
		}
		moved[widest] = true
	}
}

// writeMoved writes a moved row: its leading cells as the others are written, and its last cell on
// the next line, starting under the last column and cut to the bound.
func (t *Table) writeMoved(w io.Writer, widths []int, cells []Cell, start int) {
	last := len(cells) - 1
	// Its own cells set its own widths where they are wider than the columns, which they may be.
	own := make([]int, last)
	for i := range own {
		own[i] = cellWidth(cells[i])
		if i < len(widths) {
			own[i] = max(own[i], widths[i])
		}
	}
	t.writeLine(w, own, cells[:last])
	c := cells[last]
	if t.fit > 0 {
		c.Text = clip(c.Text, max(t.fit-start, minLastColumn))
	}
	_, _ = fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", start), t.painter.Link(c.URL, t.painter.Paint(c.Style, c.Text)))
}

// trimToFit shortens the last column so the whole row fits, and returns how many columns are left.
// A moved row's last cell is cut where it is written, on its own line.
//
// Below minLastColumn there is no sentence worth reading, so the column goes entirely rather than
// leaving a ragged edge of first words.
func (t *Table) trimToFit(widths []int, moved map[int]bool) int {
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
	for j, r := range t.rows {
		if last < len(r.cells) && !moved[j] {
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
