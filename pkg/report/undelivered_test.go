package report

import (
	"strings"
	"testing"
)

// TestUndeliveredLine covers a run that renders nothing and says nothing about it.
//
// A descriptor declares reports for publishers to deliver. With no publisher and no -o there is
// nowhere for them to go, and silence reads exactly like a run that wrote them.
func TestUndeliveredLine(t *testing.T) {
	if got := undeliveredLine(nil); got != "" {
		t.Errorf("a run with nothing undelivered should say nothing, got %q", got)
	}

	one := undeliveredLine([]string{"html"})
	if !strings.Contains(one, "html") || !strings.Contains(one, "write it") {
		t.Errorf("one report should read as one: %s", one)
	}

	// Named rather than counted: the reader's next move is deciding whether they wanted that one.
	many := undeliveredLine([]string{"html", "markdown"})
	for _, want := range []string{"html", "markdown", "write them", "-o <dir>", "publisher"} {
		if !strings.Contains(many, want) {
			t.Errorf("the line should mention %q: %s", want, many)
		}
	}
}
