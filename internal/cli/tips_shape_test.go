package cli

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// TestTipsAreShortAndShaped keeps the suggestion block from drifting into prose.
//
// A suggestion interrupts somebody reading a report, so it has to earn the interruption in the
// space of a glance. Left unchecked they grow: each one is written on its own, each addition is
// reasonable, and the block ends up longer than the findings it sits under.
//
// One shape, so they read as one voice rather than four authors: something to type, and a clause
// saying why this run makes it worth typing.
func TestTipsAreShortAndShaped(t *testing.T) {
	const (
		whatBudget = 24
		whyBudget  = 78
	)

	for _, tip := range scanTips {
		t.Run(tip.name, func(t *testing.T) {
			c := tipContext{run: engine.Result{}}
			what, why := tip.what(c), tip.why(c)
			// The left column is a flag, a command or a descriptor key. A column is only scannable
			// while every cell in it is the same kind of thing and roughly the same width.
			if n := len(what); n > whatBudget {
				t.Errorf("what is %d chars, budget %d: %q", n, whatBudget, what)
			}
			if !strings.ContainsAny(what, "-`<:") && !strings.HasPrefix(what, "draugr ") {
				t.Errorf("names no flag, setting or command to act on: %q", what)
			}
			// The right column is a clause, not a sentence. It sits beside the thing it explains,
			// so a full stop and a capital both read as something ending that had not begun.
			if n := len(why); n > whyBudget {
				t.Errorf("why is %d chars, budget %d. Say less or say it in the docs:\n%s", n, whyBudget, why)
			}
			if strings.HasSuffix(why, ".") {
				t.Errorf("a clause beside a value does not end in a full stop: %q", why)
			}
			if r := []rune(why)[0]; r >= 'A' && r <= 'Z' {
				t.Errorf("starts with a capital, which reads as a sentence in a column: %q", why)
			}
		})
	}
}
