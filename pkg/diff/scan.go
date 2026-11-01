package diff

import (
	"io"
	"strings"

	fixlist "github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// ScanView draws a scan's comparison with its base inside that scan's console report, in the
// shape this package prints for `draugr diff`. A scan given a --base and a gate on new findings is
// judged on its change, and one layout for "what did this change introduce" is one a reader learns
// once.
type ScanView struct {
	// Result is the comparison, classified and gated as `draugr diff` would classify and gate it.
	Result Result
}

var _ fixlist.ChangeView = ScanView{}

// WriteStrips draws a band strip for each state a finding can be in against the base, then one
// more labeled strip with the counts in whole.
func (v ScanView) WriteStrips(w io.Writer, label string, whole [4]int) {
	drawBandRows(w, tui.For(w), append(bandRows(v.Result.Counted()), bandRow{label, whole}))
}

// WriteListing draws what changed in the view asked for, capped at top rows where top is
// positive: the CHANGED table, one line each under compact, or WHAT TO DO under actions, then the
// findings that moved. It writes nothing where nothing changed, which the scan's verdict line
// already says, and reports whether it wrote.
func (v ScanView) WriteListing(w io.Writer, view fixlist.View, top int) bool {
	col := tui.For(w)
	r := v.Result.Counted()
	opts := Options{View: View(view), Top: top, upgradeTargets: true}
	entries := r.Changed()
	switch {
	case len(entries) == 0 && len(r.Moved) == 0:
		return false
	case len(entries) == 0:
	case opts.View == ViewActions:
		writeDiffActions(w, col, entries, r.Rules, opts)
	default:
		writeChanged(w, col, r, entries, opts)
	}
	writeMoved(w, col, r, opts)
	return true
}

// upgradeTarget is " → " and the release an upgrade action moves to, as the scan's fix list names
// it, where opts asks for one. Empty for an action that is not an upgrade, and where the fix list
// names no release.
func upgradeTarget(a action, opts Options) string {
	if !opts.upgradeTargets || a.line != nil || !strings.HasPrefix(a.what, "Upgrade ") {
		return ""
	}
	results := make([]sarif.Result, 0, len(a.group))
	for _, e := range a.group {
		results = append(results, e.Result)
	}
	if target := fixlist.UpgradeTarget(results); target != "" {
		return " → " + target
	}
	return ""
}
