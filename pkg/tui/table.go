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
}

// PlainCell is a cell that's just text.
func PlainCell(text string) Cell { return Cell{Text: text} }

// Styled is a cell that reads as the given role.
func Styled(style Style, text string) Cell { return Cell{Text: text, Style: style} }

type row struct {
	cells []Cell
	// notes are supporting lines printed under the row, indented past the first column and
	// dimmed. It's how a table says more than its columns have room for.
	notes []string
}

// Table renders aligned columns for a person reading a terminal.
//
// It exists because alignment and colour interact badly: any padding computed after styling
// counts escape bytes as visible width and the columns drift apart. text/tabwriter has the same
// flaw — its Escape mechanism hides the bytes from parsing but still measures them — so every
// command that wanted colour was going to hand-roll its own width arithmetic. Table measures
// the plain text, pads, and only then paints.
type Table struct {
	painter Painter
	indent  string
	headers []string
	rows    []row
}

// NewTable starts a table written with p. Headers may be omitted for a table whose columns
// need no labelling; when given, they're dimmed so they frame the data without competing.
func NewTable(p Painter, headers ...string) *Table {
	return &Table{painter: p, headers: headers}
}

// Indent sets a prefix for every line, for tables nested under a heading.
func (t *Table) Indent(prefix string) *Table {
	t.indent = prefix
	return t
}

// Row appends a row. Rows may be shorter than the header — missing cells render empty.
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
// column is never padded — nothing follows it, and trailing spaces are noise in a diff or a
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
			if n := width(c.Text); n > widths[i] {
				widths[i] = n
			}
		}
	}

	if len(t.headers) > 0 {
		cells := make([]Cell, len(t.headers))
		for i, h := range t.headers {
			cells[i] = Styled(StyleMuted, h)
		}
		t.writeLine(w, widths, cells)
	}
	for _, r := range t.rows {
		t.writeLine(w, widths, r.cells)
		// Align notes under the second column: far enough in to read as subordinate to the
		// row, not as rows of their own.
		pad := strings.Repeat(" ", widths[0]+columnGap)
		for _, n := range r.notes {
			_, _ = fmt.Fprintf(w, "%s%s%s\n", t.indent, pad, t.painter.Paint(StyleMuted, n))
		}
	}
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
		if !last {
			// Pad before painting: escape codes have no width on screen but plenty in a string.
			text += strings.Repeat(" ", widths[i]-width(text))
		}
		b.WriteString(t.painter.Link(c.URL, t.painter.Paint(c.Style, text)))
		if !last {
			b.WriteString(strings.Repeat(" ", columnGap))
		}
	}
	// A row whose trailing cells were empty leaves padding behind; nothing follows it.
	_, _ = fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
}

// width is a cell's display width. Counting runes rather than bytes is what makes the ✓ and ✗
// in a status column line up. It still assumes one column per rune, which is wrong for
// double-width scripts — a real problem, but not one Draugr's output has today.
func width(s string) int { return utf8.RuneCountInString(s) }
