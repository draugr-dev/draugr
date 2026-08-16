package cli

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// TestTipsAreShortAndShaped keeps the tip block from drifting into prose.
//
// A tip interrupts somebody reading a report, so it has to earn the interruption in the space of
// a glance. Left unchecked they grow: each one is written on its own, each addition is reasonable,
// and the block ends up longer than the findings it sits under.
//
// One shape, so they read as one voice rather than four authors: an observation and what to do
// about it, in one or two sentences, under the budget.
func TestTipsAreShortAndShaped(t *testing.T) {
	const budget = 140

	for _, tip := range scanTips {
		t.Run(tip.name, func(t *testing.T) {
			text := tip.text(tipContext{run: engine.Result{}})
			if n := len(text); n > budget {
				t.Errorf("%d chars, budget %d — say less or say it in the docs:\n%s", n, budget, text)
			}
			if strings.HasSuffix(text, "..") || !strings.HasSuffix(text, ".") {
				t.Errorf("a tip is a sentence and ends in a full stop: %q", text)
			}
			// Lowercase first letter: the renderer prefixes "Tip: " and a capital after it reads
			// as two sentences bolted together.
			if r := []rune(text)[0]; r >= 'A' && r <= 'Z' {
				t.Errorf("starts with a capital, which reads oddly after the prefix: %q", text)
			}
			// Every tip names the thing to do. A tip that only reports a state is an observation,
			// and the reader already has the report for those.
			if !strings.ContainsAny(text, "`-") {
				t.Errorf("names no flag, setting or command to act on: %q", text)
			}
		})
	}
}
