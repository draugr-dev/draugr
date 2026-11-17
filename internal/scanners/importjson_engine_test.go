package scanners

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/scanpolicy"
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

// beside is one run of sca over a public, critical component of one repository, trivy-fs replaying
// trivy-fs-gomod.json beside an import of the govulncheck stream at stream, held to commit where it
// names one. It returns the run and its sca findings by who reported them and the advisory, as
// `trivy-fs CVE-…` and `sarif-import CVE-…`.
func beside(t *testing.T, stream, commit string) (engine.Result, map[string]sarif.Result) {
	t.Helper()
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSCA())
	reg.RegisterScanner(replayingTrivyFS(t))
	reg.RegisterScanner(boundImport())
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{{
			Name: "api", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical,
			Repositories: []saga.Repository{{URL: t.TempDir()}},
			Imports:      []saga.Import{{Control: "sca", File: stream, Format: saga.ImportFormatGovulncheckJSON, Commit: commit}},
		}},
	}
	res, err := engine.New(reg, engine.WithPrioritization(scanpolicy.PrioritizerWith(nil, nil))).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	found := map[string]sarif.Result{}
	for _, r := range res.Controls["sca"].Report.Results {
		found[r.Scanner+" "+r.RuleID] = r
	}
	return res, found
}

// reachStream is govulncheck-reachable.json in a file of its own: CVE-2021-38561 called from main,
// and CVE-2026-56852, which trivy-fs also reports, and CVE-2020-14040, which it does not, never
// called.
func reachStream(t *testing.T) string {
	t.Helper()
	return copiedAt(t, mustRead(t, filepath.Join("testdata", "govulncheck-reachable.json")), time.Now())
}

// nativeBands are the priorities trivy-fs's findings take with no verdict about them: beside a
// govulncheck file bound to this run that found nothing.
func nativeBands(t *testing.T) map[string]string {
	t.Helper()
	_, found := beside(t, copiedAt(t, []byte(`{"config":{"scan_level":"symbol"}}`), time.Now()), boundHead)
	bands := map[string]string{}
	for key, r := range found {
		if r.Priority == "" {
			t.Fatalf("%s has no priority", key)
		}
		bands[key] = r.Priority
	}
	return bands
}

// A govulncheck file bound to the commit this run reads moves its verdicts onto trivy-fs's findings
// of the same advisories, as a govulncheck run does: the unreachable one lowers trivy-fs's finding
// and the imported copy is folded into it, and the reachable one rides on trivy-fs's finding.
func TestABoundGovulncheckFileLowersTrivyFSsUnreachableFinding(t *testing.T) {
	native := nativeBands(t)
	res, found := beside(t, reachStream(t), boundHead)
	lowered := found["trivy-fs CVE-2026-56852"]
	if r := lowered.Reachability; r == nil || r.State != sarif.ReachabilityUnreachable || r.RankedAs == "" ||
		lowered.Priority == native["trivy-fs CVE-2026-56852"] {
		t.Errorf("trivy-fs's CVE-2026-56852 at %s (native %s), reachability %+v, want govulncheck's unreachable verdict lowering it",
			lowered.Priority, native["trivy-fs CVE-2026-56852"], lowered.Reachability)
	}
	for _, folded := range []string{"sarif-import CVE-2026-56852", "sarif-import CVE-2021-38561"} {
		if _, kept := found[folded]; kept {
			t.Errorf("%s was kept beside trivy-fs's copy", folded)
		}
	}
	if r := found["trivy-fs CVE-2021-38561"].Reachability; r == nil || r.State != sarif.ReachabilityReachable || r.Analyzer != govulncheckScanner {
		t.Errorf("trivy-fs's CVE-2021-38561 reachability %+v, want govulncheck's reachable verdict", r)
	}
	if r := found["sarif-import CVE-2020-14040"].Reachability; r == nil || r.State != sarif.ReachabilityUnreachable {
		t.Errorf("CVE-2020-14040, which only the file reports: %+v", r)
	}
	if !slices.ContainsFunc(res.Reachability.Analyzers, func(a engine.AnalyzerReachability) bool {
		return a.Analyzer == govulncheckScanner && a.Reachable > 0 && a.Unreachable > 0
	}) {
		t.Errorf("reachability summary %+v", res.Reachability)
	}
}

// A govulncheck file bound to no commit lowers nothing: nothing shows its run analyzed this code, so
// trivy-fs's finding it calls unreachable keeps its native band, and so does the imported finding
// only the file reports, each undetermined. Its reachable verdict still applies, since a call path
// never makes a finding look safer.
func TestAnUnboundGovulncheckFileLowersNothing(t *testing.T) {
	native := nativeBands(t)
	_, found := beside(t, reachStream(t), "")
	kept := found["trivy-fs CVE-2026-56852"]
	if kept.Priority != native["trivy-fs CVE-2026-56852"] || (kept.Reachability != nil &&
		(kept.Reachability.State == sarif.ReachabilityUnreachable || kept.Reachability.RankedAs != "")) {
		t.Errorf("trivy-fs's CVE-2026-56852 at %s, native %s, reachability %+v, want its native band",
			kept.Priority, native["trivy-fs CVE-2026-56852"], kept.Reachability)
	}
	only, ok := found["sarif-import CVE-2020-14040"]
	if !ok || only.Reachability == nil || only.Reachability.State != sarif.ReachabilityUnknown || only.Reachability.RankedAs != "" {
		t.Errorf("CVE-2020-14040, which only the file reports: %+v, want it undetermined and unmoved", only.Reachability)
	}
	_, bound := beside(t, reachStream(t), boundHead)
	if lowered := bound["sarif-import CVE-2020-14040"]; only.Priority == lowered.Priority {
		t.Errorf("CVE-2020-14040 at %s unbound and %s bound, want the bound verdict alone to lower it", only.Priority, lowered.Priority)
	}
	if r := found["trivy-fs CVE-2021-38561"].Reachability; r == nil || r.State != sarif.ReachabilityReachable {
		t.Errorf("trivy-fs's CVE-2021-38561 reachability %+v, want the unbound file's reachable verdict", r)
	}
}
