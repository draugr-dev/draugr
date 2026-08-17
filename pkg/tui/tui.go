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
//   - a fixed, semantic palette — callers ask for "critical", not for red
//   - anything that degrades (color, hyperlinks) degrades to plain text, so piped output and
//     CI logs stay readable
package tui

import (
	"fmt"
	"io"
	"os"
	"strings"
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

// Plain returns a Painter that never colors — for tests and for building strings whose
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

// Append is Paint for a caller building a byte buffer — the log handler writes a line per
// record, and going through strings would allocate on every one.
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
// text and follow the link on click; everywhere else — an older terminal, a pipe, a CI log —
// the escape codes are absent and the text stands alone. It therefore costs no width, which is
// what makes it usable in a table that is already wide.
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
// nothing can answer, and the run then proceeds on an answer it invented — for the reader, a
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
