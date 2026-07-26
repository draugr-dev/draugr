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

// The whole reason this type exists: colour must not shift a column.
func TestColumnsAlignWhetherOrNotColoured(t *testing.T) {
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
			t.Errorf("line %d: coloured strips to %q, want %q", i, got, plain[i])
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

// Nothing follows the last column, so it must not be padded — trailing spaces are noise in a
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

// A short row is legal — the remaining columns are simply empty.
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

func TestCellLinksWhenColoured(t *testing.T) {
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

// runeIndex is strings.Index measured in runes — the unit columns are actually aligned in.
func runeIndex(s, sub string) int {
	i := strings.Index(s, sub)
	if i < 0 {
		return -1
	}
	return utf8.RuneCountInString(s[:i])
}

// stripANSI removes SGR sequences so a coloured line can be compared with its plain twin.
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
