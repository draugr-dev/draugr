package tui

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// Colour is for people at terminals. Anything else — a pipe, a file, a CI log — must receive
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
		t.Errorf("zero Painter should not colour: %q", got)
	}
	if p.Enabled() {
		t.Error("zero Painter should report colour disabled")
	}
	if got := Plain().Paint(StyleFail, "x"); got != "x" {
		t.Errorf("Plain() should not colour: %q", got)
	}
}

func TestPainterColours(t *testing.T) {
	p := Painter{color: true}
	got := p.Paint(StyleCritical, "boom")
	if !strings.HasPrefix(got, "\x1b[1;31m") || !strings.HasSuffix(got, "\x1b[0m") {
		t.Errorf("expected wrapped text, got %q", got)
	}
	if got := p.Paint(StyleNone, "plain"); got != "plain" {
		t.Errorf("StyleNone should not wrap: %q", got)
	}
}

// A hyperlink costs no visible width, which is what makes it usable in an already-wide table —
// but only where the terminal will render it.
func TestLink(t *testing.T) {
	on := Painter{color: true}
	got := on.Link("https://example.test/x", "CVE-1")
	if !strings.Contains(got, "\x1b]8;;https://example.test/x\a") || !strings.Contains(got, "CVE-1") {
		t.Errorf("expected an OSC 8 link, got %q", got)
	}
	if off := Plain().Link("https://example.test/x", "CVE-1"); off != "CVE-1" {
		t.Errorf("without colour the text must stand alone: %q", off)
	}
	if got := on.Link("", "CVE-1"); got != "CVE-1" {
		t.Errorf("no url means no link: %q", got)
	}
	// A url carrying control characters could break out of the escape sequence.
	if got := on.Link("https://x\aevil", "t"); got != "t" {
		t.Errorf("a url with control characters must not be linked: %q", got)
	}
}

// Padding is measured on the unstyled text; colouring first would inflate the length and break
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
