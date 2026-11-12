package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// A MEASURED AGAINST sentence long enough to wrap at any width a terminal is likely to have.
const measuredSentence = "checkov 3.2.0 policies · 34 of 120 checks decided, the rest need a cloud account the scan " +
	"was not given and were listed as not run, so the benchmark's score covers a little over a quarter of it"

func measuredLines(t *testing.T, columns string) []string {
	t.Helper()
	t.Setenv("COLUMNS", columns)
	var buf bytes.Buffer
	writeUnder(&buf, tui.Plain(), 14, "iac", measuredSentence)
	return strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
}

// MEASURED AGAINST wraps a control's sentence within the terminal, counting the control's column and
// the gutters in front of it, and keeps all of it: the end is the part a reader acts on.
func TestMeasuredAgainstWrapsWithinTheTerminal(t *testing.T) {
	lines := measuredLines(t, "80")
	for _, line := range lines {
		if n := utf8.RuneCountInString(line); n > 80 {
			t.Errorf("MEASURED AGAINST line is %d columns at 80: %q", n, line)
		}
	}
	got := strings.Join(lines, "\n")
	if len(lines) < 4 {
		t.Errorf("sentence took %d lines at 80 columns, want it whole over four or more:\n%s", len(lines), got)
	}
	if !strings.HasSuffix(got, "quarter of it") || strings.Contains(got, "…") {
		t.Errorf("sentence lost its end at 80 columns:\n%s", got)
	}
}

// On a terminal wider than a sentence reads well at, the sentence keeps the width it always had.
func TestMeasuredAgainstKeepsItsWidthOnAWideTerminal(t *testing.T) {
	for _, line := range measuredLines(t, "200") {
		if n := utf8.RuneCountInString(line); n > messageWidth {
			t.Errorf("MEASURED AGAINST line is %d columns on a 200-column terminal, want at most %d: %q", n, messageWidth, line)
		}
	}
}

// A failure message stays capped at three lines however narrow the terminal; only the sentences
// MEASURED AGAINST prints go uncapped.
func TestAFailureMessageStaysCappedAtThreeLines(t *testing.T) {
	if got := wrapMessage(measuredSentence+" "+measuredSentence, 40); len(got) != maxMessageLines {
		t.Errorf("wrapMessage gave %d lines, want %d", len(got), maxMessageLines)
	}
}
