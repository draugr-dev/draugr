// Package tui holds the terminal-presentation rules Draugr applies everywhere it writes for a
// person: when color is allowed, what the colors mean, and how to link to more detail.
//
// It exists because those rules were being re-derived per command. The console report, the log
// handler and the install prompt each had their own copy of the "is this a terminal" check, and
// two separate ANSI palettes had drifted apart. Output that looks assembled by different people
// is a real cost for a tool whose terminal *is* the product.
//
// The rules, in one place:
//   - color only when writing to an interactive terminal, and never when NO_COLOR is set
//     (https://no-color.org)
//   - a fixed, semantic palette, so callers ask for "critical" rather than for red
//   - anything that degrades (color, hyperlinks) degrades to plain text, so piped output and
//     CI logs stay readable
package tui

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// Style is a semantic role, not a color: callers say what a thing *is* and the palette decides
// how it looks, so the same concept renders identically in every command.
type Style string

// The palette. Severity styles mirror the report bands; the rest are roles, not colors.
const (
	StyleNone     Style = ""
	StyleCritical Style = "1;31" // bold red
	StyleHigh     Style = "31"
	StyleMedium   Style = "33"
	StyleLow      Style = "2"
	StyleFail     Style = "1;31"
	StylePass     Style = "32"
	StyleAccent   Style = "33" // draws the eye without implying severity
	StyleMuted    Style = "2"  // supporting detail: headers, labels, units
	StyleStrong   Style = "1"  // the part of a line to read first, at no cost in color
)

// Painter renders styled text, or plain text when color isn't appropriate for the destination.
// The zero value is a valid plain-text painter, so a caller that forgets to construct one
// degrades safely instead of emitting escape codes into a file.
type Painter struct{ color bool }

// For returns a Painter suited to w: color only for an interactive terminal with NO_COLOR unset.
func For(w io.Writer) Painter { return Painter{color: ColorEnabled(w)} }

// Plain returns a Painter that never colors, for tests and for building strings whose
// destination isn't known yet.
func Plain() Painter { return Painter{} }

// Colored returns a Painter for a caller that has already decided, such as one whose color
// setting comes from configuration rather than from inspecting the writer.
func Colored() Painter { return Painter{color: true} }

// Enabled reports whether this painter emits color, so callers can skip work that only matters
// when colored.
func (p Painter) Enabled() bool { return p.color }

// Paint wraps s in the style's escape codes, or returns it unchanged when color is off.
func (p Painter) Paint(style Style, s string) string {
	if !p.color || style == StyleNone {
		return s
	}
	return "\x1b[" + string(style) + "m" + s + "\x1b[0m"
}

// Append is Paint for a caller building a byte buffer, the log handler writes a line per record,
// and going through strings would allocate on every one.
func (p Painter) Append(buf []byte, style Style, s string) []byte {
	if !p.color || style == StyleNone {
		return append(buf, s...)
	}
	buf = append(buf, "\x1b["...)
	buf = append(buf, style...)
	buf = append(buf, 'm')
	buf = append(buf, s...)
	return append(buf, "\x1b[0m"...)
}

// Link renders text as an OSC 8 terminal hyperlink to url. Terminals that support it show the
// text and follow the link on click; everywhere else, an older terminal, a pipe, a CI log. The
// escape codes are absent and the text stands alone. It therefore costs no width, which is what
// makes it usable in a table that is already wide.
//
// A caller with nowhere to link should pass an empty url and get the text back.
func (p Painter) Link(url, text string) string {
	if !p.color || url == "" || strings.ContainsAny(url, "\x1b\a\n") {
		return text
	}
	return "\x1b]8;;" + url + "\a" + text + "\x1b]8;;\a"
}

// ColorEnabled reports whether colored output is appropriate for w: it must be an interactive
// terminal, and NO_COLOR must be unset.
func ColorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return IsTerminal(w)
}

// IsTerminal reports whether v (an *os.File, in practice stdin/stdout/stderr) is a character
// device. Accepts any value so it can answer for a reader (is the user there to be prompted?)
// as well as a writer (should this be colored?).
func IsTerminal(v any) bool {
	f, ok := v.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return !isDevNull(fi)
}

// isDevNull reports whether fi is the null device.
//
// The character-device test alone says yes to /dev/null, which is what a script redirects stdin
// from when it means "there is nobody here". Believing it prints a prompt into a log where
// nothing can answer, and the run then proceeds on an answer it invented, for the reader, a
// question they never saw deciding something on their behalf.
func isDevNull(fi os.FileInfo) bool {
	null, err := os.Open(os.DevNull)
	if err != nil {
		return false
	}
	defer func() { _ = null.Close() }()
	ni, err := null.Stat()
	return err == nil && os.SameFile(fi, ni)
}

// Pad left-aligns s to width, measured on the unstyled text. Padding must be computed before
// color is applied, or escape codes inflate the apparent length and columns stop lining up.
func Pad(s string, width int) string { return fmt.Sprintf("%-*s", width, s) }

// Columns reports how many character cells wide w is, or 0 when that cannot be answered.
//
// A caller that draws in place needs this, because a terminal wraps a line it cannot fit and the
// wrapped line occupies two rows. Anything that then moves the cursor back over what it drew moves
// too few rows and erases whatever is above, which is the reader's own scrollback rather than
// anything this program wrote.
//
// COLUMNS wins over the ioctl so a test, and a reader debugging a layout, can say what the width
// is without a terminal of that size.
func Columns(w io.Writer) int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	cols, _, err := term.GetSize(int(f.Fd()))
	if err != nil || cols <= 0 {
		return 0
	}
	return cols
}

// Truncate shortens s to width character cells, measuring the text a reader sees rather than the
// bytes. Zero or negative width returns s unchanged, for a caller that could not find out.
//
// Escape sequences are carried through and cost nothing, which is what makes this different from
// slicing a string: a styled line is mostly bytes the terminal never displays, so cutting by
// length removes visible text long before the edge and can cut a sequence in half, leaving the
// rest of the screen wearing a color nothing turns off. A line that is cut ends with a reset for
// the same reason, and an escape sitting exactly on the cut is kept rather than dropped, so a
// hyperlink whose text just fits is closed by its own terminator.
func Truncate(s string, width int) string {
	if width <= 0 {
		return s
	}
	var b strings.Builder
	cells, styled := 0, false
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			end := escapeEnd(s, i)
			b.WriteString(s[i:end])
			styled = true
			i = end
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if cells == width {
			if styled {
				b.WriteString("\x1b[0m")
			}
			return b.String()
		}
		b.WriteRune(r)
		cells++
		i += size
	}
	return s
}

// escapeEnd returns the index just past the escape sequence starting at i.
//
// CSI (`ESC [` … a letter) and OSC (`ESC ]` … BEL or `ESC \`) are the two a painted line contains:
// the first is color, the second is a hyperlink. An escape this does not recognize is one byte, so
// an unfamiliar sequence costs a cell rather than swallowing the line.
func escapeEnd(s string, i int) int {
	if i+1 >= len(s) {
		return len(s)
	}
	switch s[i+1] {
	case '[':
		for j := i + 2; j < len(s); j++ {
			if s[j] >= 0x40 && s[j] <= 0x7e {
				return j + 1
			}
		}
		return len(s)
	case ']':
		for j := i + 2; j < len(s); j++ {
			if s[j] == 0x07 {
				return j + 1
			}
			if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
				return j + 2
			}
		}
		return len(s)
	}
	return i + 1
}
