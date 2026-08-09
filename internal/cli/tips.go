package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/draugr-dev/draugr/internal/surfaces"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
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

// scanTip is one advisory line and the condition under which it earns its place.
type scanTip struct {
	// name identifies the tip in tests. Never printed.
	name string
	// when reports whether this run is one the tip helps with. Tips are advisory, so the bar is
	// not "is this true" but "does the reader do something differently knowing it".
	when func(tipContext) bool
	// text is the line, without the "Tip: " prefix.
	text func(tipContext) string
}

// maxTipsPerRun caps how many tips one scan may print.
//
// The limit is the feature. Every tip here is individually reasonable, and a run that prints
// five of them has taught the reader to skip the block — at which point the one that mattered is
// lost with the rest. Two is enough to be useful and few enough to still be read.
const maxTipsPerRun = 2

// scanTips is the tip library, in descending order of what a reader gains from it. The first
// maxTipsPerRun whose condition holds are printed.
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
			return c.opts.failOnPriority == "" && !c.opts.noGate &&
				c.verdict.Verdict == norn.Pass && countAtOrAbove(c.run, "P2") > 0
		},
		text: func(c tipContext) string {
			n := countAtOrAbove(c.run, "P2")
			return fmt.Sprintf("this run passed with %d P1/P2 finding(s) — severity thresholds do not "+
				"look at priority. Add --fail-on-priority P2 to gate on risk as well.", n)
		},
	},
	{
		// A report rendered to a CI log and nowhere else is the failure this catches: the run
		// worked, and the evidence lives only in a log somebody has to go and find.
		name: "publish",
		// --no-publish is respected rather than ignored: a caller who has said not to publish is
		// not asking where the report should go. The diff workflow scans both sides of a pull
		// request with exactly that flag.
		when: func(c tipContext) bool {
			return inCI() && c.opts.outputDir == "" && len(c.model.Config.Publishers) == 0 && !c.opts.noPublish
		},
		text: func(tipContext) string {
			return "this looks like CI, and the report exists only in this log. Use -o <dir> to keep " +
				"it as an artifact, or config.publishers to send it to code scanning or a PR comment."
		},
	},
	{
		name: "classify",
		when: func(c tipContext) bool {
			return hasFindings(c.run) && !usesRiskClassification(c.model)
		},
		text: func(tipContext) string {
			return "no components set exposure/criticality, so priorities use severity alone. " +
				"Run `draugr classify` to make P1–P4 reflect real risk."
		},
	},
	{
		// Gated on the run having been slow enough for a cache to be worth the directory. Below
		// that, the advice costs the reader more attention than it saves them time.
		name: "cache",
		when: func(c tipContext) bool {
			return c.opts.cacheDir == "" && c.run.Stats.Duration >= cacheTipThreshold
		},
		text: func(c tipContext) string {
			return fmt.Sprintf("this run took %s and cached nothing. --cache-dir <dir> reuses results "+
				"for inputs that have not changed.", c.run.Stats.Duration.Round(time.Second))
		},
	},
}

// cacheTipThreshold is how long a run must take before suggesting a cache is worth the words.
const cacheTipThreshold = 60 * time.Second

// printScanTips writes the uncovered-surface note and up to maxTipsPerRun contextual hints after
// a console scan — small nudges that help someone new to security get more out of Draugr. Tips
// are advisory and never affect the verdict. They are suppressed by --no-tips or the
// DRAUGR_NO_TIPS environment variable.
func printScanTips(w io.Writer, c tipContext) {
	if c.opts.noTips || tipsDisabled() || c.model == nil {
		return
	}
	printUncoveredSurfaceNote(w, c.model)

	shown := 0
	for _, tip := range scanTips {
		if shown == maxTipsPerRun {
			return
		}
		if !tip.when(c) {
			continue
		}
		_, _ = fmt.Fprintf(w, "\nTip: %s\n", tip.text(c))
		shown++
	}
}

// printUncoveredSurfaceNote reports the surfaces this descriptor declares that no enabled control
// looks at.
//
// Not a tip and not counted against the tip budget: the tips describe a run that could be more
// useful, and this describes one whose result covers less than the reader will assume it does.
func printUncoveredSurfaceNote(w io.Writer, model *saga.Model) {
	lines := surfaces.Uncovered(model)
	if len(lines) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\nNot checked:\n")
	for _, l := range lines {
		_, _ = fmt.Fprintf(w, "      %s\n", l)
	}
	// Named here because it is absent everywhere else. A reader who knows Draugr has a `dast`
	// control, and sees a host listed as unchecked without it, reads the omission as a gap in
	// this note rather than as the deliberate choice it is.
	if surfaces.DeclaresHosts(model) {
		_, _ = fmt.Fprint(w, "      dast is never suggested — it sends attack traffic. Enable it yourself.\n")
	}
	_, _ = fmt.Fprint(w, "      draugr controls — what each control does\n")
}

// countAtOrAbove counts findings whose priority is at or above a band.
func countAtOrAbove(run engine.Result, band string) int {
	n := 0
	for _, cr := range run.Controls {
		for _, r := range cr.Report.Results {
			if r.Suppressed() {
				continue
			}
			if r.Priority != "" && r.Priority <= band {
				n++
			}
		}
	}
	return n
}

// inCI reports whether this looks like an automated run.
//
// Deliberately the generic variable rather than a list of vendors: every major CI system sets
// `CI`, and a list of the ones we thought of would be wrong for whichever one a reader uses.
func inCI() bool { return os.Getenv("CI") != "" }

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

// usesRiskClassification reports whether any component declares an exposure or criticality — the
// inputs that make priority ranking risk-aware rather than severity-only.
func usesRiskClassification(model *saga.Model) bool {
	for _, c := range model.Components {
		if c.Exposure != "" || c.Criticality != "" {
			return true
		}
	}
	return false
}

// hasFindings reports whether the run produced at least one finding across all controls.
func hasFindings(run engine.Result) bool {
	for _, cr := range run.Controls {
		if len(cr.Report.Results) > 0 {
			return true
		}
	}
	return false
}
