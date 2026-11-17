package scanners

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// replayingTrivyFS is trivy-fs reporting trivy-fs-gomod.json over every checkout.
func replayingTrivyFS(t *testing.T) plugin.Scanner {
	t.Helper()
	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkoutAt, nil, nil, nil
	trivy.runLogged = trivyFSRun(func(context.Context, string, []string) ([]byte, []byte, error) {
		return importTestdata(t, "trivy-fs-gomod.json"), nil, nil
	})
	return trivy
}

// textAdvisories are the four golang.org/x/text advisories trivy-fs-gomod.json reports.
var textAdvisories = []string{"CVE-2021-38561", "CVE-2022-32149", "CVE-2026-56851", "CVE-2026-56852"}

// Trivy's own JSON imported into sca beside trivy-fs over the same go.mod, in two components of a
// repository each: each advisory is counted once per component, the row naming the other copy, the
// imported one as `imported trivy (trivy-json)`.
func TestAnImportedTrivyJSONBesideTrivyFSCountsEachAdvisoryOnce(t *testing.T) {
	comps := twoComponents("trivy-fs-gomod.json")
	for name, c := range comps {
		c.format = saga.ImportFormatTrivyJSON
		comps[name] = c
	}
	res, _ := runBesideImport(t, controllers.NewSCA(), replayingTrivyFS(t), saga.ControllerSettings{"enabled": true}, comps)
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	got := countedFlaws(t, res, "sca")
	for _, comp := range []string{"api", "web"} {
		if len(got[comp]) != len(textAdvisories) {
			t.Fatalf("%s: counted %+v, want each advisory once", comp, got[comp])
		}
		for _, f := range got[comp] {
			if !slices.Contains(textAdvisories, f.rule) || len(f.also) != 1 ||
				(f.also[0] != "trivy" && f.also[0] != "imported trivy (trivy-json)") {
				t.Errorf("%s %s: also found by %v, want the other Trivy copy", comp, f.rule, f.also)
			}
		}
	}
}

// In a component of two repositories a tool's JSON, which names no repository, is placed in
// neither, so its findings merge with no native copy and stay counted apart, rather than joining a
// copy in a repository the file may not be about.
func TestAnImportedTrivyJSONInTwoRepositoriesMergesWithNoNativeCopy(t *testing.T) {
	res, _ := runBesideImport(t, controllers.NewSCA(), replayingTrivyFS(t), saga.ControllerSettings{"enabled": true},
		map[string]importComponent{"api": {
			repos: []string{"service", "tools"}, file: filepath.Join("testdata", "sarif-import", "trivy-fs-gomod.json"),
			format: saga.ImportFormatTrivyJSON,
		}})
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	imported, native := 0, 0
	for _, r := range res.Controls["sca"].Report.Results {
		switch {
		case r.Scanner == plugin.ImportScanner && !r.Correlated() && r.Correlation == nil:
			imported++
		case r.Scanner != plugin.ImportScanner:
			native++
		}
	}
	if imported != len(textAdvisories) || native != 2*len(textAdvisories) {
		t.Errorf("imported %d counted apart, native %d, want %d imported apart beside %d native",
			imported, native, len(textAdvisories), 2*len(textAdvisories))
	}
}

// govulncheck's own JSON imported into sca beside trivy-fs: its verdict reaches trivy-fs's finding
// of the same advisory in the same go.mod, as a govulncheck run's does, and the imported copy is
// folded away; an advisory trivy-fs did not report keeps the imported finding with its verdict.
func TestAnImportedGovulncheckVerdictReachesTrivyFSsFinding(t *testing.T) {
	stream := copiedAt(t, mustRead(t, filepath.Join("testdata", "govulncheck-reachable.json")), time.Now())
	res, _ := runBesideImport(t, controllers.NewSCA(), replayingTrivyFS(t), saga.ControllerSettings{"enabled": true},
		map[string]importComponent{"api": {repos: []string{"api"}, file: stream, format: saga.ImportFormatGovulncheckJSON}})
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	var called, unreached *sarif.Result
	results := res.Controls["sca"].Report.Results
	for i, r := range results {
		switch {
		case r.RuleID == "CVE-2021-38561" && r.Scanner == plugin.ImportScanner:
			t.Errorf("the imported copy of CVE-2021-38561 was kept beside trivy-fs's")
		case r.RuleID == "CVE-2021-38561":
			called = &results[i]
		case r.RuleID == "CVE-2020-14040":
			unreached = &results[i]
		}
	}
	if called == nil || called.Reachability == nil || called.Reachability.State != sarif.ReachabilityReachable ||
		called.Reachability.Analyzer != govulncheckScanner {
		t.Fatalf("trivy-fs's CVE-2021-38561: %+v, want govulncheck's reachable verdict", called)
	}
	if unreached == nil || unreached.Scanner != plugin.ImportScanner || unreached.Reachability == nil ||
		unreached.Reachability.State != sarif.ReachabilityUnreachable {
		t.Errorf("CVE-2020-14040, which only the file reports: %+v", unreached)
	}
	if !slices.ContainsFunc(res.Reachability.Analyzers, func(a engine.AnalyzerReachability) bool {
		return a.Analyzer == govulncheckScanner && a.Reachable > 0
	}) {
		t.Errorf("reachability summary %+v names no verdict of govulncheck's", res.Reachability)
	}
}
