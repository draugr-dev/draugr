package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/surfaces"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// tipContext is everything a tip may be gated on: the descriptor, what the run produced, the
// verdict it reached, and the flags the caller actually typed.
//
// Gathered into one struct so a tip's condition is a pure function of it. That is what makes the
// gates testable without a scan, and it is the property that keeps this list from turning into
// the place where console logic accumulates.
type tipContext struct {
	model   *saga.Model
	run     engine.Result
	verdict norn.Result
	opts    *scanOptions
}

// gatesOnSeverity reports whether this run was judged on a finding's own severity rather than on
// the band it landed in. The two are exclusive, and which one it is decides whether half the advice
// here applies at all.
func (c tipContext) gatesOnSeverity() bool {
	if c.opts.failOn != "" {
		return true
	}
	if c.opts.failOnPriority != "" {
		return false
	}
	kind, _ := c.model.Config.Gate.Resolved()
	return kind == saga.GateSeverity
}

// scanTip is one thing worth trying and the condition under which it earns its place.
type scanTip struct {
	// name identifies the tip in tests. Never printed.
	name string
	// when reports whether this run is one the tip helps with. Tips are advisory, so the bar is
	// not "is this true" but "does the reader do something differently knowing it".
	when func(tipContext) bool
	// what to type, or the key to add to the descriptor.
	what func(tipContext) string
	// why, in a clause that fits beside it.
	why func(tipContext) string
}

// maxTipsPerRun caps how many tips one scan may print.
//
// The limit is the feature. Every tip here is individually reasonable, and a run that prints five
// of them has taught the reader to skip the block, at which point the one that mattered is lost
// with the rest. Two is enough to be useful and few enough to still be read.
const maxTipsPerRun = 2

// scanTips is the tip library, in descending order of what a reader gains from it. The first
// maxTipsPerRun whose condition holds are offered.
//
// Ordered by consequence rather than by how often each fires: a run that both passed with P1
// findings ungated and took a long time without a cache has one problem worth naming and one
// convenience, and they should not compete on equal terms.
var scanTips = []scanTip{
	{
		// A pass that would have been a fail under a priority gate is the one case here where
		// the reader's mental model of the run is wrong rather than merely incomplete.
		name: "priority-gate",
		when: func(c tipContext) bool {
			// Only where the gate asks about severity. Under the default it already asks about
			// the band, and telling somebody to add the gate they are already running is advice
			// that reads as the product not knowing what it did.
			return c.gatesOnSeverity() && !c.opts.noGate &&
				c.verdict.Verdict == norn.Pass && countAtOrAbove(c.run, "P2") > 0
		},
		what: func(tipContext) string { return "--fail-on P2" },
		why: func(c tipContext) string {
			return fmt.Sprintf("this passed on severity with %d P1/P2 %s",
				countAtOrAbove(c.run, "P2"), plural2(countAtOrAbove(c.run, "P2"), "finding", "findings"))
		},
	},
	{
		// A descriptor written by hand describes what a team builds, so "self" is the right default.
		// One written by a surveyor describes a running cluster, where most images come from somebody
		// else, and there the fix list tells the reader to upgrade libraries inside images they cannot
		// rebuild, which is advice they cannot take.
		name: "built-upstream",
		when: func(c tipContext) bool {
			return hasImageFindings(c.run) && !declaresBuiltBy(c.model)
		},
		what: func(tipContext) string { return "builtBy: upstream" },
		why: func(tipContext) string {
			return "the fix list says to upgrade packages inside images you do not build"
		},
	},
	{
		// Gated on the run having been slow enough for a cache to be worth the directory. Below
		// that, the advice costs the reader more attention than it saves them time.
		name: "cache",
		when: func(c tipContext) bool {
			return c.opts.cacheDir == "" && c.run.Stats.Duration >= cacheTipThreshold
		},
		what: func(tipContext) string { return "--cache-dir <dir>" },
		why: func(c tipContext) string {
			return fmt.Sprintf("this run took %s and cached nothing",
				c.run.Stats.Duration.Round(time.Second))
		},
	},
	{
		// Only where something went unexamined, which is when a reader has a reason to go and read
		// what the controls are. On every other run it is a row that never changes.
		name: "controls",
		when: func(c tipContext) bool { return len(surfaces.Gaps(c.model)) > 0 },
		what: func(tipContext) string { return "draugr controls" },
		why:  func(tipContext) string { return "what each control looks at, and what turns it on" },
	},
}

// cacheTipThreshold is how long a run must take before suggesting a cache is worth the words.
const cacheTipThreshold = 60 * time.Second

// printUncoveredSurfaceNote names what a descriptor declares and no enabled control looks at.
//
// For `doctor`, which answers "is this set up" and where a declared surface nothing examines is
// part of the answer. A scan reports the same facts through the report itself, beside the verdict
// they qualify.
func printUncoveredSurfaceNote(w io.Writer, model *saga.Model) {
	gaps := surfaces.Gaps(model)
	if len(gaps) == 0 {
		return
	}
	col := tui.For(w)
	_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, "NOT CHECKED"))
	t := tui.NewTable(col).Indent("  ")
	for _, g := range gaps {
		t.Row(tui.Styled(tui.StyleStrong, g.Component+" "+g.Surface),
			tui.Styled(tui.StyleMuted, fmt.Sprintf("%d %s off: %s", len(g.Controls),
				plural2(len(g.Controls), "control", "controls"), strings.Join(g.Controls, ", "))))
	}
	t.Render(w)
}

// uncoveredFor is what the descriptor declares and no enabled control examines, in the report's
// own terms.
func uncoveredFor(model *saga.Model) []report.Gap {
	if model == nil {
		return nil
	}
	gaps := surfaces.Gaps(model)
	out := make([]report.Gap, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, report.Gap{Component: g.Component, Surface: g.Surface, Controls: g.Controls})
	}
	return out
}

// scanSuggestions is what this run makes worth trying, for the report's own block.
//
// Returned rather than printed. They were a second block of loose lines under a report that had
// just finished with one, each a sentence naming a flag in the middle of it, and a reader looking
// for something to type had to read all of them to find out which applied. The report has a place
// for this now, and one place beats two.
//
// Suppressed by --no-tips or DRAUGR_NO_TIPS, which is what those have always meant: the advisory
// rows go and the ones describing the report itself stay.
func scanSuggestions(c tipContext) []report.Suggestion {
	if c.opts.noTips || tipsDisabled() || c.model == nil {
		return nil
	}
	out := make([]report.Suggestion, 0, maxTipsPerRun)
	for _, tip := range scanTips {
		if len(out) == maxTipsPerRun {
			break
		}
		if !tip.when(c) {
			continue
		}
		out = append(out, report.Suggestion{What: tip.what(c), Why: tip.why(c)})
	}
	return out
}

// countAtOrAbove counts findings whose priority is at or above a band.
func countAtOrAbove(run engine.Result, band string) int {
	n := 0
	for _, cr := range run.Controls {
		for _, r := range cr.Report.Results {
			if r.Suppressed() {
				continue
			}
			// A second scanner's copy of a flaw already counted. Without this the tip told a
			// reader that enabling the opt-in matcher had doubled their urgent work, when it had
			// found the same flaws twice.
			if r.Correlated() {
				continue
			}
			if r.Priority != "" && r.Priority <= band {
				n++
			}
		}
	}
	return n
}

// plural2 picks between two forms by count.
func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// sortedKeys returns a map's keys in order, so the note is stable between runs.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// tipsDisabled reports whether tips are globally turned off via the environment.
func tipsDisabled() bool { return os.Getenv("DRAUGR_NO_TIPS") != "" }

// usesRiskClassification reports whether any component declares an exposure or criticality. The
// inputs that make priority ranking risk-aware rather than severity-only.
func usesRiskClassification(model *saga.Model) bool {
	for _, c := range model.Components {
		if c.Exposure != "" || c.Criticality != "" {
			return true
		}
	}
	return false
}

// hasImageFindings reports whether the run found anything in a container image.
func hasImageFindings(run engine.Result) bool {
	c, ok := run.Controls["images"]
	return ok && len(c.Report.Results) > 0
}

// declaresBuiltBy reports whether any image says who builds it.
//
// Any, not all: a descriptor that has answered the question once has been told about it, and
// repeating the advice for the images it left at the default would be nagging about a decision
// somebody has already made.
// declaresBuiltBy reports whether anything in the descriptor says who publishes it.
//
// A component-wide declaration counts: it covers every target under it, and a descriptor that has
// said who publishes its images should not be nagged to say it again per image.
func declaresBuiltBy(model *saga.Model) bool {
	if model == nil {
		return false
	}
	for _, c := range model.Components {
		if c.BuiltBy != "" {
			return true
		}
		for _, img := range c.Images {
			if img.BuiltBy != "" {
				return true
			}
		}
	}
	return false
}
