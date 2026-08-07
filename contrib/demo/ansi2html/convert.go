// Command ansi2html turns a real coloured scan into an HTML fragment for the website's home
// page.
//
// The home page needs the shape of an answer — one command, five controls, one verdict, a
// non-zero exit — in the three seconds a visitor gives it. A screenshot of the whole scan is the
// wrong tool for that: it is a wall of findings, it is two hundred kilobytes, it does not scale
// with the reader's zoom, and nothing in it can be selected or indexed.
//
// Text solves all of that, and hand-written text drifts: nothing connects a fragment somebody
// typed to the scan it claims to show, so it ends up describing a different run from the image
// beside it. Generating it from the real thing is what makes "sleek" and "true" stop being a
// trade-off — the fragment is a few hundred bytes of real output, and it cannot go stale while
// the job that produces it keeps running.
//
// Reads a coloured scan on stdin (a PTY is required for Draugr to emit colour at all) and writes
// the fragment on stdout.
package main

import (
	"fmt"
	"html"
	"strings"
)

// styleClass maps the SGR codes pkg/tui emits to CSS classes the site defines.
//
// The map is the whole palette and nothing else. Several roles share a code — critical and fail
// are both "1;31", accent and medium are both "33" — so the stream cannot tell them apart and
// neither can this: the classes are named for the colour's weight rather than for a role it
// might be carrying. An unrecognised code is an error rather than plain text, because the way
// this fails otherwise is that the palette grows, the home page quietly loses a colour, and
// nothing says so.
var styleClass = map[string]string{
	"1;31": "t-crit",
	"31":   "t-high",
	"33":   "t-warn",
	"2":    "t-dim",
	"32":   "t-pass",
}

// options configure the shell framing around the captured output.
type options struct {
	// command is echoed above the output as a shell prompt line. Empty omits it.
	command string
	// stopAt truncates at the first line beginning with this prefix. Empty keeps everything.
	stopAt string
	// exitCode is echoed below the output as `$ echo $?`. Negative omits it.
	exitCode int
}

// convert renders a coloured terminal capture as an HTML fragment.
func convert(in string, opts options) (string, error) {
	body, err := renderLines(trim(in, opts.stopAt))
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(`<pre class="term">`)
	if opts.command != "" {
		b.WriteString(prompt(opts.command))
		b.WriteString("\n")
	}
	b.WriteString(body)
	if opts.exitCode >= 0 {
		// A blank line between: it is a second command, not a continuation of the output.
		b.WriteString("\n\n")
		b.WriteString(prompt("echo $?"))
		fmt.Fprintf(&b, "\n%d", opts.exitCode)
	}
	b.WriteString("</pre>")
	return b.String(), nil
}

// prompt renders a shell prompt line. The `$` and the command are ours, not Draugr's — they are
// the context that makes the block readable as a session, and they are the only part of the
// fragment that is not captured output.
func prompt(cmd string) string {
	return `<span class="t-prompt">$</span> ` + html.EscapeString(cmd)
}

// trim drops everything from the first line starting with prefix.
//
// Used to cut the findings table: it is the least distinctive thing a scanner prints, it is what
// makes the frame a wall, and the page links to the full output for anyone who wants it. Line
// prefixes are safe to match on because a style never spans a newline — pkg/tui closes every
// escape it opens on the same line.
func trim(in, prefix string) string {
	in = strings.ReplaceAll(in, "\r\n", "\n")
	in = strings.ReplaceAll(in, "\r", "")
	if prefix == "" {
		return in
	}
	lines := strings.Split(in, "\n")
	for i, line := range lines {
		if strings.HasPrefix(stripSGR(line), prefix) {
			return strings.Join(lines[:i], "\n")
		}
	}
	return in
}

// renderLines converts the escape sequences in s to markup, trailing blank lines removed.
func renderLines(s string) (string, error) {
	out, err := render(strings.TrimRight(s, "\n \t"))
	if err != nil {
		return "", err
	}
	return out, nil
}

// render walks s, converting SGR colour runs and OSC 8 hyperlinks and escaping everything else.
func render(s string) (string, error) {
	var b strings.Builder
	var text strings.Builder // pending plain text, escaped on flush
	openSpan, openLink := false, false

	flush := func() {
		b.WriteString(html.EscapeString(text.String()))
		text.Reset()
	}
	closeSpan := func() {
		if openSpan {
			b.WriteString("</span>")
			openSpan = false
		}
	}

	for i := 0; i < len(s); {
		if s[i] != 0x1b {
			text.WriteByte(s[i])
			i++
			continue
		}
		flush()

		switch {
		case strings.HasPrefix(s[i:], "\x1b["):
			end := strings.IndexByte(s[i:], 'm')
			if end < 0 {
				return "", fmt.Errorf("unterminated escape at byte %d", i)
			}
			code := s[i+2 : i+end]
			i += end + 1
			if code == "0" || code == "" {
				closeSpan()
				continue
			}
			class, ok := styleClass[code]
			if !ok {
				return "", fmt.Errorf("unmapped SGR code %q at byte %d — add it to styleClass "+
					"and give the site a rule for it, or the home page loses this colour silently", code, i)
			}
			closeSpan()
			b.WriteString(`<span class="`)
			b.WriteString(class)
			b.WriteString(`">`)
			openSpan = true

		case strings.HasPrefix(s[i:], "\x1b]8;;"):
			end := strings.IndexByte(s[i:], '\a')
			if end < 0 {
				return "", fmt.Errorf("unterminated hyperlink at byte %d", i)
			}
			url := s[i+5 : i+end]
			i += end + 1
			if url == "" {
				if openLink {
					b.WriteString("</a>")
					openLink = false
				}
				continue
			}
			b.WriteString(`<a href="`)
			b.WriteString(html.EscapeString(url))
			b.WriteString(`">`)
			openLink = true

		default:
			return "", fmt.Errorf("unrecognised escape sequence at byte %d", i)
		}
	}
	flush()
	closeSpan()
	if openLink {
		b.WriteString("</a>")
	}
	return b.String(), nil
}

// stripSGR removes colour escapes so a line can be matched on its text.
func stripSGR(line string) string {
	for {
		start := strings.IndexByte(line, 0x1b)
		if start < 0 {
			return line
		}
		end := strings.IndexAny(line[start:], "m\a")
		if end < 0 {
			return line[:start]
		}
		line = line[:start] + line[start+end+1:]
	}
}
