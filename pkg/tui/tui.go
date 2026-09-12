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
//
// The values are the sixteen-color codes every terminal has had since the 1980s, and they are
// what a caller gets unless the terminal says it can do better. See exact, which carries the
// same roles in the project's own colors.
const (
	StyleNone     Style = ""
	StyleCritical Style = "1;31" // bold red
	StyleHigh     Style = "31"
	StyleMedium   Style = "33"
	StyleLow      Style = "2"
	StyleFail     Style = "1;31"
	StylePass     Style = "32"
	StyleAccent   Style = "33"   // draws the eye without implying severity
	StyleInfo     Style = "36"   // a band that is neither urgent nor negligible
	StyleFixed    Style = "1;32" // the release that ends a finding
	StyleMuted    Style = "2"    // supporting detail: headers, labels, units
	StyleStrong   Style = "1"    // the part of a line to read first, at no cost in color
)

// exact renders a role in the color the rest of the product uses for it, for a terminal that can
// show all of them.
//
// Sixteen-color red is whatever the reader's theme decided red is, and across the dashboard, the
// HTML report and the terminal that produced one red per surface. A band is a piece of
// vocabulary, so it should be the same color wherever somebody meets it, and a terminal
// announcing twenty-four-bit color can be held to that.
//
// Keyed by the sixteen-color value rather than by the constant. Roles that share a code are the
// same color today, and keying this way keeps them the same color here rather than letting the two
// palettes disagree about which roles are alike.
// #nosec G101 -- SGR parameter strings, which a credential scanner reads as high-entropy values.
var exact = map[Style]Style{
	StyleCritical: "1;38;2;229;83;75",
	StyleHigh:     "38;2;229;83;75",
	StyleMedium:   "38;2;232;184;75",
	StyleMuted:    "38;2;120;131;141",
	StylePass:     "38;2;87;171;90",
	StyleFixed:    "1;38;2;87;171;90",
	StyleInfo:     "38;2;124;166;184",
}

// chipColors is the filled form of a role: the band's color behind text dark or light enough to
// read on it.
//
// A filled label is how a band is drawn everywhere else, and it does something a colored word
// cannot: the count and the band read as one object rather than as two words that happen to be
// adjacent. The foregrounds are picked for contrast against their own background rather than
// taken from the palette.
var chipColors = map[Style]struct{ bg, fg string }{
	StyleCritical: {"229;83;75", "18;6;5"},
	StyleHigh:     {"229;83;75", "18;6;5"},
	StyleMedium:   {"232;184;75", "22;17;10"},
	StyleInfo:     {"124;166;184", "10;17;22"},
	StyleMuted:    {"107;118;128", "255;255;255"},
	StylePass:     {"87;171;90", "6;18;10"},
}

// Painter renders styled text, or plain text when color isn't appropriate for the destination.
// The zero value is a valid plain-text painter, so a caller that forgets to construct one
// degrades safely instead of emitting escape codes into a file.
type Painter struct {
	color bool
	// full is whether the terminal can show the project's own colors rather than the sixteen
	// every terminal has.
	full bool
}

// For returns a Painter suited to w: color only for an interactive terminal with NO_COLOR unset.
func For(w io.Writer) Painter { return Painter{color: ColorEnabled(w), full: FullColor()} }

// Plain returns a Painter that never colors, for tests and for building strings whose
// destination isn't known yet.
func Plain() Painter { return Painter{} }

// Colored returns a Painter for a caller that has already decided, such as one whose color
// setting comes from configuration rather than from inspecting the writer.
func Colored() Painter { return Painter{color: true} }

// FullColorPainter is Colored for a caller that has also decided the terminal can show the
// project's own colors. Used by the tests that pin what those look like.
func FullColorPainter() Painter { return Painter{color: true, full: true} }

// Enabled reports whether this painter emits color, so callers can skip work that only matters
// when colored.
func (p Painter) Enabled() bool { return p.color }

// Paint wraps s in the style's escape codes, or returns it unchanged when color is off.
func (p Painter) Paint(style Style, s string) string {
	if !p.color || style == StyleNone {
		return s
	}
	return "\x1b[" + string(p.resolve(style)) + "m" + s + "\x1b[0m"
}

// resolve picks the rendering of a role for this terminal.
func (p Painter) resolve(style Style) Style {
	if !p.full {
		return style
	}
	if e, ok := exact[style]; ok {
		return e
	}
	return style
}

// Chip renders text as a filled label in the role's color, the shape a band wears everywhere else
// Draugr shows one.
//
// It degrades twice rather than once. A terminal with full color gets the color itself; a
// sixteen-color terminal gets the role reversed, which fills the same area in whatever red or
// yellow that terminal calls the role; and a destination with no color at all, a pipe or a CI log,
// gets the bare text, because a chip with no fill is a word with two extra spaces around it.
func (p Painter) Chip(style Style, text string) string {
	if !p.color || style == StyleNone {
		return text
	}
	if c, ok := chipColors[style]; ok && p.full {
		return "\x1b[48;2;" + c.bg + ";38;2;" + c.fg + "m " + text + " \x1b[0m"
	}
	return "\x1b[7;" + string(style) + "m " + text + " \x1b[0m"
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

// FullColor reports whether the terminal says it can show twenty-four-bit color.
//
// COLORTERM is the only signal there is: TERM describes a terminal type from a database that
// mostly predates the capability, and probing means writing a color and reading back what the
// terminal made of it, which a program writing to a pipe cannot do. An absent variable is read as
// "no", so the sixteen-color rendering is what an unknown terminal gets.
func FullColor() bool {
	switch os.Getenv("COLORTERM") {
	case "truecolor", "24bit":
		return true
	}
	return false
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

// PriorityStyle is the color a band wears, everywhere the product draws one.
//
// P3 had no color of its own once and was drawn in whatever the terminal's text color is, which is
// also what an unranked row and a heading look like. Three of four bands being distinguishable is
// not a ramp.
func PriorityStyle(band string) Style {
	switch strings.ToUpper(band) {
	case "P1":
		return StyleFail
	case "P2":
		return StyleMedium
	case "P3":
		return StyleInfo
	case "P4":
		return StyleMuted
	}
	return StyleNone
}

// BandChips renders the four counts as filled labels.
//
// Filled, because that is how a band is drawn everywhere else and it does something a colored word
// cannot: the count and the band read as one object rather than two words that happen to be
// adjacent. A band with nothing in it stays on the row and says zero, so the shape of the ramp is
// learnable from any run.
func (p Painter) BandChips(counts [4]int) string {
	labels := [4]string{"P1", "P2", "P3", "P4"}
	parts := make([]string, 0, len(counts))
	for i, n := range counts {
		text := labels[i] + " " + strconv.Itoa(n)
		if n == 0 {
			parts = append(parts, p.Paint(StyleMuted, text))
			continue
		}
		parts = append(parts, p.Chip(PriorityStyle(labels[i]), text))
	}
	// One space, because a filled chip carries its own.
	return strings.Join(parts, " ")
}
