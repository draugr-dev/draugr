package tui

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func render(t *testing.T, tb *Table) []string {
	t.Helper()
	var b bytes.Buffer
	tb.Render(&b)
	return strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
}

// The whole reason this type exists: color must not shift a column.
func TestColumnsAlignWhetherOrNotColored(t *testing.T) {
	build := func(p Painter) *Table {
		return NewTable(p, "Tool", "Status").
			Row(PlainCell("git"), Styled(StylePass, "✓ found")).
			Row(PlainCell("gitleaks"), Styled(StyleFail, "✗ missing"))
	}
	plain := render(t, build(Plain()))
	colored := render(t, build(Colored()))
	if len(plain) != len(colored) {
		t.Fatalf("line counts differ: %d vs %d", len(plain), len(colored))
	}
	for i := range plain {
		if got := stripANSI(colored[i]); got != plain[i] {
			t.Errorf("line %d: colored strips to %q, want %q", i, got, plain[i])
		}
	}
	// And the alignment is real: the status column starts at the same offset on every row.
	want := runeIndex(plain[0], "Status")
	for i, line := range plain[1:] {
		if got := runeIndex(line, "✓"); got != -1 && got != want {
			t.Errorf("row %d status starts at %d, want %d: %q", i, got, want, line)
		}
	}
}

// A multi-byte glyph is one column wide, not three.
func TestWidthCountsRunesNotBytes(t *testing.T) {
	lines := render(t, NewTable(Plain(), "A", "B").
		Row(PlainCell("✓✓✓"), PlainCell("x")).
		Row(PlainCell("abc"), PlainCell("y")))
	// Compare rune offsets: byte offsets are exactly the mistake this guards against.
	if runeIndex(lines[1], "x") != runeIndex(lines[2], "y") {
		t.Errorf("multi-byte cell threw off the column:\n%s\n%s", lines[1], lines[2])
	}
}

func TestHeadersAreDimmedAndOptional(t *testing.T) {
	var b bytes.Buffer
	NewTable(Colored(), "Tool").Row(PlainCell("git")).Render(&b)
	if !strings.Contains(b.String(), "\x1b["+string(StyleMuted)+"m") {
		t.Errorf("header should be dimmed: %q", b.String())
	}
	lines := render(t, NewTable(Plain()).Row(PlainCell("git")))
	if len(lines) != 1 || lines[0] != "git" {
		t.Errorf("headerless table = %q, want just the row", lines)
	}
}

// Nothing follows the last column, so it must not be padded. Trailing spaces are noise in a
// diff, a copied log or a golden test.
func TestNoTrailingWhitespace(t *testing.T) {
	for _, line := range render(t, NewTable(Plain(), "A", "B").
		Row(PlainCell("long-value"), PlainCell("x")).
		Row(PlainCell("s"), PlainCell("much-longer-value"))) {
		if line != strings.TrimRight(line, " ") {
			t.Errorf("trailing whitespace: %q", line)
		}
	}
}

func TestRowWithNoteIsIndentedUnderTheSecondColumn(t *testing.T) {
	lines := render(t, NewTable(Plain(), "Priority", "Rule").
		RowWithNote("what it actually means", PlainCell("P1"), PlainCell("CVE-1")))
	if len(lines) != 3 {
		t.Fatalf("want header, row, note; got %q", lines)
	}
	// "Priority" is the widest first-column value, so the note starts past it.
	if want := len("Priority") + 2; runeIndex(lines[2], "what") != want {
		t.Errorf("note starts at %d, want %d: %q", runeIndex(lines[2], "what"), want, lines[2])
	}
}

func TestIndentAppliesToEveryLine(t *testing.T) {
	for _, line := range render(t, NewTable(Plain(), "A").Indent("  ").Row(PlainCell("x"))) {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("missing indent: %q", line)
		}
	}
}

// A short row is legal. The remaining columns are simply empty.
func TestShortRowsAndEmptyTable(t *testing.T) {
	lines := render(t, NewTable(Plain(), "A", "B", "C").Row(PlainCell("only")))
	if len(lines) != 2 || strings.TrimSpace(lines[1]) != "only" {
		t.Errorf("short row = %q", lines)
	}
	var b bytes.Buffer
	NewTable(Plain()).Render(&b)
	if b.Len() != 0 {
		t.Errorf("empty table wrote %q", b.String())
	}
}

func TestCellLinksWhenColored(t *testing.T) {
	var b bytes.Buffer
	NewTable(Colored(), "Rule").
		Row(Cell{Text: "CVE-1", URL: "https://example.test/CVE-1"}).Render(&b)
	if !strings.Contains(b.String(), "\x1b]8;;https://example.test/CVE-1\a") {
		t.Errorf("want an OSC 8 link: %q", b.String())
	}
	var plain bytes.Buffer
	NewTable(Plain(), "Rule").
		Row(Cell{Text: "CVE-1", URL: "https://example.test/CVE-1"}).Render(&plain)
	if strings.Contains(plain.String(), "example.test") {
		t.Errorf("a link must not become visible text off a terminal: %q", plain.String())
	}
}

// runeIndex is strings.Index measured in runes. The unit columns are actually aligned in.
func runeIndex(s, sub string) int {
	i := strings.Index(s, sub)
	if i < 0 {
		return -1
	}
	return utf8.RuneCountInString(s[:i])
}

// stripANSI removes SGR sequences so a colored line can be compared with its plain twin.
func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

// A table is bounded by a terminal rather than by its content. The last column gives way because
// nothing follows it and because it is the prose: an identifier or a location is useless
// shortened, where a sentence is readable shortened and still readable gone.
func TestFitTrimsTheLastColumn(t *testing.T) {
	build := func(width int) string {
		var b strings.Builder
		NewTable(Plain(), "Rule", "Summary").Indent("  ").Fit(width).
			Row(PlainCell("CVE-2019-20477"), PlainCell("command execution through a constructor")).
			Row(PlainCell("CVE-2018-1000656"), PlainCell("denial of service via crafted JSON")).
			Render(&b)
		return b.String()
	}

	// Wide enough for everything: nothing is touched.
	full := build(200)
	if !strings.Contains(full, "command execution through a constructor") {
		t.Errorf("a table that fits was trimmed:\n%s", full)
	}
	// Narrow: the sentence is cut at a word, and says it was cut.
	narrow := build(50)
	for _, line := range strings.Split(strings.TrimRight(narrow, "\n"), "\n") {
		if n := len([]rune(line)); n > 50 {
			t.Errorf("line is %d cells, past the 50 it was given: %q", n, line)
		}
	}
	if !strings.Contains(narrow, "…") {
		t.Errorf("a cut line should say so:\n%s", narrow)
	}
	// Cut at a word. A fragment reads as a different word, and a reader cannot tell which they
	// are looking at.
	if !strings.Contains(narrow, " a…") {
		t.Errorf("cut mid-word, which reads as a different word:\n%s", narrow)
	}
	// Narrower than a sentence is worth: the column goes, and takes its heading with it.
	gone := build(40)
	if strings.Contains(gone, "Summary") || strings.Contains(gone, "…") {
		t.Errorf("a column with no room left should go entirely:\n%s", gone)
	}
	if !strings.Contains(gone, "CVE-2019-20477") {
		t.Errorf("the columns that fit must survive:\n%s", gone)
	}
	// No width to respect, which is what a file or a pipe gives: nothing is guessed at.
	if build(0) != full {
		t.Errorf("a table given no width should be as wide as its content:\n%s", build(0))
	}
}

// A cell can carry a second, quieter part, and the column still lines up: the width is measured on
// both halves, so a qualifier does not push the next column out on the rows that have one.
func TestStyledNotesAndCellNotesKeepTheColumns(t *testing.T) {
	var b strings.Builder
	NewTable(Colored(), "Upgrade", "Where").Indent("  ").StyledNotes().
		RowWithNote("\x1b[2malready painted\x1b[0m",
			Cell{Text: "Flask 0.12.2 →", Note: "0.12.3", NoteStyle: StyleFixed},
			PlainCell("requirements.txt:1")).
		Row(PlainCell("x"), PlainCell("y")).
		Render(&b)
	out := b.String()
	// The note the caller painted is set as given rather than dimmed a second time.
	if strings.Contains(out, "\x1b[2m\x1b[2malready painted") {
		t.Errorf("a painted note was painted again:\n%q", out)
	}
	if !strings.Contains(out, "already painted") {
		t.Errorf("the note is missing:\n%q", out)
	}
	// Both halves of the cell are there, each in its own style.
	if !strings.Contains(out, "Flask 0.12.2 →") || !strings.Contains(out, "0.12.3") {
		t.Errorf("the cell lost a half:\n%q", out)
	}
}
