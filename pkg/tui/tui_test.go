package tui

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// Color is for people at terminals. Anything else, a pipe, a file, a CI log. Must receive
// plain text, or the escape codes end up in the artifact.
func TestColorOnlyForTerminals(t *testing.T) {
	if ColorEnabled(&bytes.Buffer{}) {
		t.Error("a buffer is not a terminal")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if ColorEnabled(w) {
		t.Error("a pipe is not a terminal")
	}
	t.Setenv("NO_COLOR", "1")
	if ColorEnabled(os.Stdout) {
		t.Error("NO_COLOR must win even on a terminal")
	}
}

func TestPainterPlainByDefault(t *testing.T) {
	// The zero value must be safe: a caller who forgets to construct one emits plain text
	// rather than escape codes.
	var p Painter
	if got := p.Paint(StyleCritical, "x"); got != "x" {
		t.Errorf("zero Painter should not color: %q", got)
	}
	if p.Enabled() {
		t.Error("zero Painter should report color disabled")
	}
	if got := Plain().Paint(StyleFail, "x"); got != "x" {
		t.Errorf("Plain() should not color: %q", got)
	}
}

func TestPainterColors(t *testing.T) {
	p := Painter{color: true}
	got := p.Paint(StyleCritical, "boom")
	if !strings.HasPrefix(got, "\x1b[1;31m") || !strings.HasSuffix(got, "\x1b[0m") {
		t.Errorf("expected wrapped text, got %q", got)
	}
	if got := p.Paint(StyleNone, "plain"); got != "plain" {
		t.Errorf("StyleNone should not wrap: %q", got)
	}
}

// A hyperlink costs no visible width, which is what makes it usable in an already-wide table,
// but only where the terminal will render it.
func TestLink(t *testing.T) {
	on := Painter{color: true}
	got := on.Link("https://example.test/x", "CVE-1")
	if !strings.Contains(got, "\x1b]8;;https://example.test/x\a") || !strings.Contains(got, "CVE-1") {
		t.Errorf("expected an OSC 8 link, got %q", got)
	}
	if off := Plain().Link("https://example.test/x", "CVE-1"); off != "CVE-1" {
		t.Errorf("without color the text must stand alone: %q", off)
	}
	if got := on.Link("", "CVE-1"); got != "CVE-1" {
		t.Errorf("no url means no link: %q", got)
	}
	// A url carrying control characters could break out of the escape sequence.
	if got := on.Link("https://x\aevil", "t"); got != "t" {
		t.Errorf("a url with control characters must not be linked: %q", got)
	}
}

// Padding is measured on the unstyled text; coloring first would inflate the length and break
// every column in the table.
func TestPad(t *testing.T) {
	if got := Pad("ab", 5); got != "ab   " {
		t.Errorf("Pad = %q", got)
	}
	if got := Pad("toolong", 3); got != "toolong" {
		t.Errorf("Pad must not truncate: %q", got)
	}
}

func TestIsTerminal(t *testing.T) {
	if IsTerminal(&bytes.Buffer{}) {
		t.Error("a buffer is not a terminal")
	}
	if IsTerminal(nil) {
		t.Error("nil is not a terminal")
	}
}

// For decides from the destination: a buffer is not a terminal, so nothing is colored.
func TestForPicksFromTheWriter(t *testing.T) {
	if For(&bytes.Buffer{}).Enabled() {
		t.Error("a buffer is not a terminal")
	}
	if got := For(&bytes.Buffer{}).Paint(StyleFail, "x"); got != "x" {
		t.Errorf("Paint = %q, want plain", got)
	}
}

// Append is Paint for callers building byte buffers; the two must agree exactly, or the log
// and the report drift apart again.
func TestAppendMatchesPaint(t *testing.T) {
	for _, p := range []Painter{Plain(), Colored()} {
		for _, style := range []Style{StyleNone, StyleFail, StyleMuted} {
			want := p.Paint(style, "hello")
			got := string(p.Append([]byte("pre:"), style, "hello"))
			if got != "pre:"+want {
				t.Errorf("color=%v style=%q: Append = %q, want %q", p.Enabled(), style, got, "pre:"+want)
			}
		}
	}
}

func TestIsTerminalRejectsTheNullDevice(t *testing.T) {
	// /dev/null is a character device, so the mode test alone says yes. And it is exactly what a
	// script redirects stdin from when it means there is nobody here. Prompting into that prints
	// a question nothing can answer, then acts on the answer it invents.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("no %s on this platform: %v", os.DevNull, err)
	}
	defer func() { _ = null.Close() }()
	if IsTerminal(null) {
		t.Error("the null device is not somebody to ask")
	}
}

func TestIsTerminalRejectsAFileAndANonFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if IsTerminal(f) {
		t.Error("a regular file is not a terminal")
	}
	if IsTerminal("not a file") {
		t.Error("a non-file is not a terminal")
	}
}

func TestTruncateMeasuresWhatTheReaderSees(t *testing.T) {
	red := "\x1b[31m"
	reset := "\x1b[0m"
	for _, tc := range []struct {
		name, in string
		width    int
		want     string
	}{
		{"shorter than the window is untouched", "abc", 10, "abc"},
		{"exactly the window is untouched", "abcde", 5, "abcde"},
		{"longer is cut to the window", "abcdefgh", 5, "abcde"},
		{"an unknown width cuts nothing", "abcdefgh", 0, "abcdefgh"},
		{
			// The bytes a terminal never displays must not count against the width, or a colored
			// line loses most of its text while a plain one keeps all of it.
			name: "color costs no cells", in: red + "abcdefgh" + reset, width: 5,
			want: red + "abcde" + reset,
		},
		{
			// Cutting inside a styled span leaves the color on, and the terminal wears it for
			// everything printed afterwards.
			name: "a cut line turns its color off", in: red + "abcdefgh", width: 3,
			want: red + "abc" + reset,
		},
		{name: "a cut plain line needs no reset", in: "abcdefgh", width: 3, want: "abc"},
		{
			name: "a hyperlink costs only its text",
			in:   "\x1b]8;;https://example.com/a/very/long/url\x07link\x1b]8;;\x07after",
			// The escape carries a URL far longer than the window and still occupies no cells.
			width: 4,
			// The closing terminator sits exactly on the cut and is kept, so the link ends where
			// its text does rather than running to the end of the screen.
			want: "\x1b]8;;https://example.com/a/very/long/url\x07link\x1b]8;;\x07" + reset,
		},
		{name: "multibyte text counts runes, not bytes", in: "✓✓✓✓✓", width: 3, want: "✓✓✓"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Truncate(tc.in, tc.width); got != tc.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
			}
		})
	}
}

func TestColumnsPrefersTheEnvironment(t *testing.T) {
	t.Setenv("COLUMNS", "72")
	if got := Columns(io.Discard); got != 72 {
		t.Errorf("Columns = %d, want 72", got)
	}
	for _, v := range []string{"", "0", "-1", "wide"} {
		t.Setenv("COLUMNS", v)
		// io.Discard is not a file, so there is nothing to ask and no width to invent. A caller
		// that gets 0 leaves its output alone, which is the safe answer.
		if got := Columns(io.Discard); got != 0 {
			t.Errorf("COLUMNS=%q: Columns = %d, want 0", v, got)
		}
	}
}

// An escape this does not understand, or one the line ends in the middle of, must not swallow the
// rest of the string: a frame cut mid-sequence is what a truncating writer produces, and a reader
// of it would otherwise lose everything after.
func TestTruncateSurvivesAMalformedEscape(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		width    int
		want     string
	}{
		{name: "a CSI with no final byte", in: "\x1b[31", width: 4, want: "\x1b[31"},
		{name: "a hyperlink with no terminator", in: "\x1b]8;;http://x", width: 4, want: "\x1b]8;;http://x"},
		{name: "an ESC at the very end", in: "ab\x1b", width: 4, want: "ab\x1b"},
		// Not a sequence this knows, so it costs one cell rather than eating the line.
		{name: "an escape with no introducer", in: "\x1bXabcd", width: 3, want: "\x1bXab\x1b[0m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Truncate(tc.in, tc.width); got != tc.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
			}
		})
	}
}

// Not a terminal, so there is no size to ask for and none is invented.
func TestColumnsIsZeroForAFileThatIsNotATerminal(t *testing.T) {
	t.Setenv("COLUMNS", "")
	f, err := os.CreateTemp(t.TempDir(), "cols")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if got := Columns(f); got != 0 {
		t.Errorf("Columns of a regular file = %d, want 0", got)
	}
}
