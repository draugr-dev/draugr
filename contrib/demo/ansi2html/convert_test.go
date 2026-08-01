package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/tui"
)

func TestConvertRendersAColouredLine(t *testing.T) {
	p := tui.Colored()
	in := "Draugr — " + p.Paint(tui.StyleFail, "FAIL") + "   " + p.Paint(tui.StyleMuted, "(draugr-demo 1.0)")

	got, err := convert(in, options{exitCode: -1})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	want := `<pre class="term">Draugr — <span class="t-crit">FAIL</span>   ` +
		`<span class="t-dim">(draugr-demo 1.0)</span></pre>`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestConvertEscapesTheText(t *testing.T) {
	// Scanner messages carry angle brackets and ampersands — a rule about `<script>` in a finding
	// title would otherwise be injected into the page that renders this.
	got, err := convert(`use -o <dir> & "quotes"`, options{exitCode: -1})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if strings.Contains(got, "<dir>") {
		t.Errorf("angle brackets not escaped: %s", got)
	}
	for _, want := range []string{"&lt;dir&gt;", "&amp;"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
}

func TestConvertFramesTheSession(t *testing.T) {
	got, err := convert("Draugr — FAIL", options{command: "draugr scan .", exitCode: 1})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	// The exit code is the point of the block: it is what makes this a gate rather than a report.
	for _, want := range []string{
		`<span class="t-prompt">$</span> draugr scan .`,
		"\n\n" + `<span class="t-prompt">$</span> echo $?`,
		"\n1</pre>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestConvertOmitsTheExitLineWhenNegative(t *testing.T) {
	got, err := convert("x", options{exitCode: -1})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if strings.Contains(got, "echo $?") {
		t.Errorf("exit line should be absent: %s", got)
	}
}

func TestConvertStopsAtTheFindingsTable(t *testing.T) {
	p := tui.Colored()
	in := strings.Join([]string{
		"Controls:",
		"  " + p.Paint(tui.StyleAccent, "sca") + "  FAIL",
		"",
		p.Paint(tui.StyleAccent, "Fix first") + " (top 10 of 272, by priority):",
		"  P1  critical  9.8",
	}, "\n")

	got, err := convert(in, options{stopAt: "Fix first", exitCode: -1})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if strings.Contains(got, "Fix first") || strings.Contains(got, "critical") {
		t.Errorf("the findings table should be cut:\n%s", got)
	}
	if !strings.Contains(got, "Controls:") {
		t.Errorf("everything above it should survive:\n%s", got)
	}
	// Cut before the escapes are parsed, so a coloured heading is matched on its text.
	if strings.Contains(got, "\x1b") {
		t.Errorf("raw escape survived: %q", got)
	}
}

func TestConvertTrimsTrailingBlankLines(t *testing.T) {
	// A capture ends with the shell's next prompt stripped off, leaving blank lines that would
	// otherwise render as dead space under the block.
	got, err := convert("Draugr — FAIL\n\n\n", options{exitCode: -1})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.HasSuffix(got, "FAIL</pre>") {
		t.Errorf("trailing blank lines survived: %q", got)
	}
}

func TestConvertRendersAHyperlink(t *testing.T) {
	// Rule ids are OSC 8 links in the console. They are below the cut today, but the converter
	// must not emit the escape bytes into the page if the cut ever moves.
	in := tui.Colored().Link("https://example.test/CVE-1", "CVE-1")
	got, err := convert(in, options{exitCode: -1})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	want := `<a href="https://example.test/CVE-1">CVE-1</a>`
	if !strings.Contains(got, want) {
		t.Errorf("got %s, want it to contain %s", got, want)
	}
}

func TestConvertRejectsAnUnmappedColour(t *testing.T) {
	// The guard that matters: if the palette grows and nobody updates the map, this fails the
	// build rather than publishing a home page that has quietly lost a colour.
	_, err := convert("\x1b[35mmagenta\x1b[0m", options{exitCode: -1})
	if err == nil {
		t.Fatal("expected an error for an unmapped SGR code")
	}
	if !strings.Contains(err.Error(), "35") {
		t.Errorf("the error should name the code: %v", err)
	}
}

func TestConvertRejectsAMalformedEscape(t *testing.T) {
	for name, in := range map[string]string{
		"unterminated colour": "red \x1b[31",
		"unterminated link":   "\x1b]8;;https://example.test",
		"unknown sequence":    "\x1b?weird",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := convert(in, options{exitCode: -1}); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestConvertNormalisesCarriageReturns(t *testing.T) {
	// A PTY capture is CRLF-delimited; left in, every line would carry a stray character.
	got, err := convert("one\r\ntwo\r\n", options{exitCode: -1})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if strings.Contains(got, "\r") {
		t.Errorf("carriage return survived: %q", got)
	}
	if !strings.Contains(got, "one\ntwo") {
		t.Errorf("got %q", got)
	}
}

// TestStyleClassCoversThePalette holds the map to pkg/tui rather than to a copy of it.
//
// The console's palette is the source of truth, and this file's whole job is to translate it. A
// style added there and forgotten here does not break anything visibly: the fragment simply
// fails to build, which is the right outcome — but only if something checks, and this is it.
func TestStyleClassCoversThePalette(t *testing.T) {
	palette := []tui.Style{
		tui.StyleCritical, tui.StyleHigh, tui.StyleMedium, tui.StyleLow,
		tui.StyleFail, tui.StylePass, tui.StyleAccent, tui.StyleMuted,
	}
	for _, s := range palette {
		if s == tui.StyleNone {
			continue
		}
		if _, ok := styleClass[string(s)]; !ok {
			t.Errorf("pkg/tui emits SGR %q and styleClass has no entry for it — add one, and a "+
				"matching rule in the site's stylesheet", s)
		}
	}
}

func TestRunReadsStdinAndWritesTheFragment(t *testing.T) {
	var out bytes.Buffer
	if err := run(strings.NewReader("Draugr — FAIL"), &out, options{exitCode: -1}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.HasPrefix(out.String(), `<pre class="term">`) {
		t.Errorf("got %q", out.String())
	}
}

func TestRunReportsAConversionFailure(t *testing.T) {
	var out bytes.Buffer
	if err := run(strings.NewReader("\x1b[35mx\x1b[0m"), &out, options{exitCode: -1}); err == nil {
		t.Fatal("expected the unmapped colour to fail the run")
	}
}

func TestTrimKeepsEverythingWhenThePrefixIsAbsent(t *testing.T) {
	// If the console heading is reworded, the cut silently stops happening — the fragment gets
	// long rather than wrong, which is why the workflow checks the fragment's size afterwards.
	got := trim("one\ntwo", "Fix first")
	if got != "one\ntwo" {
		t.Errorf("got %q, want the input unchanged", got)
	}
}

func TestTrimSurvivesATruncatedEscape(t *testing.T) {
	// stripSGR runs before the parser has rejected anything, so it meets whatever the capture
	// held. It must not panic or loop on a sequence that never terminates.
	if got := trim("head\nx\x1b[", "nope"); got != "head\nx\x1b[" {
		t.Errorf("got %q", got)
	}
}

// failingReader stands in for a broken stdin.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errRead }

var errRead = fmt.Errorf("read failed")

func TestRunReportsAReadFailure(t *testing.T) {
	var out bytes.Buffer
	if err := run(failingReader{}, &out, options{exitCode: -1}); err == nil {
		t.Fatal("expected the read failure to surface")
	}
}
