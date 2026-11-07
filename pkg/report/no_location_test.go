package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding the scanner gave no location says so where its location would be, in the console's
// block and compact views, markdown and HTML, for findings in each of two repositories.
func TestAFindingWithNoLocationSaysTheScannerGaveNone(t *testing.T) {
	d := Data{Project: "svc", Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Control: "sast", Report: sarif.Report{Tool: "gosec", Results: []sarif.Result{
			{RuleID: "G115", Level: sarif.LevelError, Priority: "P1", Component: "api", Repository: "https://example.com/a.git",
				Message: "integer overflow conversion int -> int32"},
			{RuleID: "G115", Level: sarif.LevelWarning, Priority: "P2", Component: "api", Repository: "https://example.com/b.git",
				Message: "integer overflow conversion uint64 -> int64"},
		}}},
	}}}
	for name, c := range map[string]struct {
		r    Reporter
		view View
	}{
		"console": {consoleReporter{}, ""}, "compact": {consoleReporter{}, ViewCompact},
		"markdown": {markdownReporter{}, ""}, "html": {htmlReporter{}, ""},
	} {
		d.View = c.view
		out := renderWith(t, c.r, d)
		if got := strings.Count(out, noLocation); got < 2 {
			t.Errorf("%s: %q appears %d times, want once per finding:\n%s", name, noLocation, got, out)
		}
	}
}
