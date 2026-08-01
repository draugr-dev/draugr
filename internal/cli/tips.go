package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// printScanTips writes contextual, one-line hints after a console scan — small nudges that help
// someone new to security get more out of Draugr. Tips are advisory and never affect the verdict.
// They are suppressed by --no-tips or the DRAUGR_NO_TIPS environment variable, and only shown when
// there are findings to contextualize.
func printScanTips(w io.Writer, model *saga.Model, run engine.Result, noTips bool) {
	if noTips || tipsDisabled() || model == nil {
		return
	}
	// Not gated on findings, unlike the classification tip below. A surface nothing checks is
	// most worth saying when the report is empty — that is precisely when a reader concludes
	// there is nothing to find.
	if lines := uncoveredSurfaces(model); len(lines) > 0 {
		_, _ = fmt.Fprintf(w, "\nNote: nothing checks part of what this descriptor declares.\n")
		for _, l := range lines {
			_, _ = fmt.Fprintf(w, "      %s\n", l)
		}
		_, _ = fmt.Fprint(w, "      Run `draugr controls` to see what each control does.\n")
	}
	if !hasFindings(run) {
		return
	}
	if !usesRiskClassification(model) {
		_, _ = fmt.Fprint(w, "\nTip: no components set exposure/criticality, so priorities use severity "+
			"alone. Run `draugr classify` to make P1–P4 reflect real risk.\n")
	}
}

// uncoveredSurfaces names each component surface that no enabled control looks at.
//
// A descriptor that declares a `hosts:` entry with the host controls off scans everything about
// that component except the thing it exposes to the internet, and says nothing. The run is a
// clean pass over a surface nobody looked at — the same shape as a scan that enables no control
// at all, which fails loudly, but with a smaller blast radius and no signal whatsoever.
//
// A note rather than a failure: the choice may be deliberate, and refusing to scan because a
// control is off would be worse than the gap. Suppressed by --no-tips / DRAUGR_NO_TIPS.
func uncoveredSurfaces(model *saga.Model) []string {
	var out []string
	for i := range model.Components {
		c := &model.Components[i]
		for _, surface := range sortedKeys(controlsForSurface) {
			if !componentHasSurface(c, surface) {
				continue
			}
			var off []string
			for _, name := range controlsForSurface[surface] {
				if !c.ControllerEnabled(name, model.Config) {
					off = append(off, name)
				}
			}
			// Partial cover is still cover: one enabled control means someone is looking.
			if len(off) == len(controlsForSurface[surface]) {
				out = append(out, fmt.Sprintf("%s declares %s, and %s %s not enabled",
					c.Name, surface, strings.Join(off, ", "), plural2(len(off), "is", "are")))
			}
		}
	}
	return out
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
