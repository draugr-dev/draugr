package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// One advisory on a package two lockfiles hold is one finding at two locations: correlation counts
// the second copy under the first. The ACCEPTED rows count it as the bands and report.json's
// suppressed total do, once, and say how many locations, for a setting's row and for
// config.exclude's, in each of two repositories.
func TestAcceptedRowsCountFindingsAndTheirLocations(t *testing.T) {
	copyOf := func(repo, file, rule string, sup *sarif.Suppression, counted bool) sarif.Result {
		r := sarif.Result{RuleID: rule, Level: sarif.LevelError, Priority: "P1", Component: "app", Repository: repo,
			Tool: "grype", Location: sarif.Location{URI: file, StartLine: 1}, Suppression: sup}
		if !counted {
			r.Correlation = &sarif.Correlation{CountedUnder: "grype"}
		}
		return r
	}
	setting := func() *sarif.Suppression {
		return &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting,
			Justification: sarif.JustificationCPEMatch, Source: "config.controls.sca.cpeMatches"}
	}
	exclude := func() *sarif.Suppression {
		return &sarif.Suppression{Kind: "external", Origin: "saga", Justification: "accepted", Source: "draugr.saga.yaml", Line: 9}
	}
	var results []sarif.Result
	for _, repo := range []string{"one", "two"} {
		results = append(results,
			copyOf(repo, "ios/Podfile.lock", "CVE-2022-3095", setting(), true),
			copyOf(repo, "example/ios/Podfile.lock", "CVE-2022-3095", setting(), false),
			copyOf(repo, "a/package-lock.json", "CVE-2024-1", exclude(), true),
			copyOf(repo, "b/package-lock.json", "CVE-2024-1", exclude(), false))
	}
	d := Data{Project: "app", Run: engine.Result{Suppressed: 4, Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{Tool: "grype", Results: results}},
	}}}
	out := renderWith(t, consoleReporter{}, d)
	for _, want := range []string{
		"config.exclude                            2 findings suppressed at 4 locations",
		"config.controls.sca.cpeMatches: suppress  2 findings suppressed at 4 locations · matched by CPE only",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// A finding at one location says nothing about locations.
	if got := suppressedCount(3, 3); got != "3 findings suppressed" {
		t.Errorf("suppressedCount(3, 3) = %q", got)
	}
	// The rows sum to what report.json counts: suppressed and not a correlated copy.
	total := 0
	for _, r := range results {
		if r.Suppressed() && !r.Correlated() {
			total++
		}
	}
	rows := 0
	for _, r := range settingRows(d) {
		rows += r.n
	}
	if f, _ := excludedCounts(d); f+rows != total {
		t.Errorf("rows sum to %d, report.json counts %d", f+rows, total)
	}
}
