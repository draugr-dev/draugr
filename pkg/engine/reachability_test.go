package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// scanned is a finding as a manifest scanner reports it: no reachability of its own.
func scanned(repo, rule, pkg string) sarif.Result {
	return sarif.Result{
		Tool: "trivy", RuleID: rule, Level: sarif.LevelError, Repository: repo,
		Component: "api", Package: &sarif.Package{Name: pkg, Version: "v0.3.0"},
	}
}

// analyzed is the same finding as a reachability analyzer reports it.
func analyzed(repo, rule, pkg string, state sarif.ReachabilityState) sarif.Result {
	return sarif.Result{
		Tool: "govulncheck", RuleID: rule, Level: sarif.LevelWarning, Repository: repo,
		Component: "api", Package: &sarif.Package{Name: pkg, Version: "v0.3.0"},
		Reachability: &sarif.Reachability{State: state, Analyzer: "govulncheck", Method: "call-graph"},
	}
}

func TestApplyReachabilityFoldsRatherThanDuplicating(t *testing.T) {
	// The reason this is an enrichment and not a second scanner. Both tools report the same
	// vulnerability under different identifiers; reporting both would double every Go finding,
	// which is the opposite of what reachability is for.
	ctrls := controlsWith(
		scanned("repo-a", "CVE-2022-32149", "golang.org/x/text"),
		analyzed("repo-a", "CVE-2022-32149", "golang.org/x/text", sarif.ReachabilityReachable),
	)
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})

	res := ctrls["sca"].Report.Results
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1, the analyzer's copy should fold away", len(res))
	}
	if res[0].Tool != "trivy" {
		t.Errorf("kept tool = %q, want the scanner that rated it", res[0].Tool)
	}
	if res[0].Reachability == nil || res[0].Reachability.State != sarif.ReachabilityReachable {
		t.Fatalf("verdict did not move onto the finding: %+v", res[0].Reachability)
	}
	if got.Reachable != 1 || len(got.Analyzers) != 1 || got.Analyzers[0].Analyzer != "govulncheck" {
		t.Errorf("summary = %+v, want 1 reachable from govulncheck", got)
	}
}

func TestApplyReachabilityKeepsWhatNothingElseReported(t *testing.T) {
	// A vulnerability only one tool found is exactly the one that must not disappear in a
	// deduplication. The Go standard library is the case that produces it.
	ctrls := controlsWith(
		analyzed("repo-a", "CVE-2024-24790", "stdlib", sarif.ReachabilityReachable),
	)
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})

	if n := len(ctrls["sca"].Report.Results); n != 1 {
		t.Fatalf("results = %d, want the unmatched finding kept", n)
	}
	if len(got.Analyzers) != 1 || got.Analyzers[0].Contributed != 1 {
		t.Errorf("summary = %+v, want 1 contributed", got)
	}
}

func TestApplyReachabilityDoesNotCollapseRepositories(t *testing.T) {
	// One repository proves the fold runs; two prove it does not pick a winner. The same module
	// can be called in one repository of a component and merely required in another, and a key
	// without the repository would report whichever was indexed last for both.
	ctrls := controlsWith(
		scanned("repo-calls", "CVE-2022-32149", "golang.org/x/text"),
		scanned("repo-quiet", "CVE-2022-32149", "golang.org/x/text"),
		analyzed("repo-calls", "CVE-2022-32149", "golang.org/x/text", sarif.ReachabilityReachable),
		analyzed("repo-quiet", "CVE-2022-32149", "golang.org/x/text", sarif.ReachabilityUnreachable),
	)
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})

	byRepo := map[string]sarif.ReachabilityState{}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Reachability != nil {
			byRepo[r.Repository] = r.Reachability.State
		}
	}
	if byRepo["repo-calls"] != sarif.ReachabilityReachable {
		t.Errorf("repo-calls = %q, want reachable", byRepo["repo-calls"])
	}
	if byRepo["repo-quiet"] != sarif.ReachabilityUnreachable {
		t.Errorf("repo-quiet = %q, want unreachable", byRepo["repo-quiet"])
	}
	if got.Reachable != 1 || got.Unreachable != 1 {
		t.Errorf("summary = %+v, want one of each", got)
	}
}

func TestApplyReachabilityRebandsAndRecordsWhy(t *testing.T) {
	// Reachability feeds the priority matrix rather than rewriting severity, so the band moves
	// and the reported severity does not. And the finding says which severity it was ranked at.
	ctrls := controlsWith(
		scanned("repo-a", "CVE-2020-14040", "golang.org/x/text"),
		analyzed("repo-a", "CVE-2020-14040", "golang.org/x/text", sarif.ReachabilityUnreachable),
	)
	ctrls["sca"].Report.Results[0].Priority = "P1"

	e := &Engine{prioritize: func(_ string, _ saga.Exposure, _ saga.Criticality, res sarif.Result) Priority {
		if res.Reachability != nil && res.Reachability.State == sarif.ReachabilityUnreachable {
			return Priority{Band: "P2", RankedAs: sarif.SeverityMedium}
		}
		return Priority{Band: "P1"}
	}}
	e.applyReachability(ctrls, saga.Model{})

	res := ctrls["sca"].Report.Results[0]
	if res.Priority != "P2" {
		t.Errorf("priority = %q, want P2, the band should have moved", res.Priority)
	}
	if res.Level != sarif.LevelError {
		t.Errorf("level = %q, want the scanner's own rating, unchanged", res.Level)
	}
	if res.Reachability.RankedAs != sarif.SeverityMedium {
		t.Errorf("rankedAs = %q, want medium recorded on the finding", res.Reachability.RankedAs)
	}
}

func TestApplyReachabilityGivesEachFindingItsOwnVerdict(t *testing.T) {
	// One analyzer verdict covers every identifier an advisory is known by, but RankedAs is a
	// fact about one finding's severity. A shared struct would record whichever was banded last.
	shared := &sarif.Reachability{State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck"}
	a := analyzed("repo-a", "CVE-1111-1", "m", sarif.ReachabilityUnreachable)
	b := analyzed("repo-a", "CVE-2222-2", "m", sarif.ReachabilityUnreachable)
	a.Reachability, b.Reachability = shared, shared
	ctrls := controlsWith(
		scanned("repo-a", "CVE-1111-1", "m"), scanned("repo-a", "CVE-2222-2", "m"), a, b,
	)
	e := &Engine{prioritize: func(_ string, _ saga.Exposure, _ saga.Criticality, res sarif.Result) Priority {
		if res.RuleID == "CVE-1111-1" {
			return Priority{Band: "P2", RankedAs: sarif.SeverityMedium}
		}
		return Priority{Band: "P4", RankedAs: sarif.SeverityLow}
	}}
	e.applyReachability(ctrls, saga.Model{})

	got := map[string]sarif.Severity{}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Reachability != nil {
			got[r.RuleID] = r.Reachability.RankedAs
		}
	}
	if got["CVE-1111-1"] == got["CVE-2222-2"] {
		t.Errorf("both findings recorded %q, the verdict was shared, not copied", got["CVE-1111-1"])
	}
}

func TestApplyReachabilityNoAnalyzerIsANoop(t *testing.T) {
	ctrls := controlsWith(scanned("repo-a", "CVE-2022-32149", "golang.org/x/text"))
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})
	if got.Ran() || got.Reachable+got.Unreachable+got.Unknown != 0 {
		t.Errorf("summary = %+v, want zero when nothing analyzed", got)
	}
	if len(ctrls["sca"].Report.Results) != 1 {
		t.Error("findings must be untouched when no analyzer ran")
	}
}

func TestApplyReachabilityCountsUndetermined(t *testing.T) {
	// Unknown is reported rather than folded into a total: it says how much of the answer is
	// missing, and an unreachable count alone cannot express that.
	ctrls := controlsWith(
		scanned("repo-a", "CVE-2022-32149", "golang.org/x/text"),
		analyzed("repo-a", "CVE-2022-32149", "golang.org/x/text", sarif.ReachabilityUnknown),
	)
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})
	if got.Unknown != 1 || got.Unreachable != 0 {
		t.Errorf("summary = %+v, want one undetermined and no unreachable", got)
	}
}

func TestClassificationOfReadsTheDescriptor(t *testing.T) {
	model := saga.Model{Components: []saga.Component{
		{Name: "api", Exposure: saga.Exposure("public"), Criticality: saga.Criticality("important")},
	}}
	if exp, crit := classificationOf(model, "api"); exp != "public" || crit != "important" {
		t.Errorf("got %q/%q, want public/important", exp, crit)
	}
	// A project-scoped finding belongs to no component, and gets the zero classification.
	if exp, crit := classificationOf(model, "nope"); exp != "" || crit != "" {
		t.Errorf("got %q/%q, want empty for an unknown component", exp, crit)
	}
}

func TestPackageNameHandlesFindingsThatAreNotAboutAPackage(t *testing.T) {
	if got := packageName(sarif.Result{}); got != "" {
		t.Errorf("packageName = %q, want empty", got)
	}
	if got := packageName(sarif.Result{Package: &sarif.Package{Name: "flask"}}); got != "flask" {
		t.Errorf("packageName = %q, want flask", got)
	}
}

func TestApplyReachabilityKeepsAnalyzersApartInTheSummary(t *testing.T) {
	// Two analyzers can run. They cover different ecosystems, and a summary naming one is a
	// report that is right about half of itself.
	a := analyzed("repo-a", "CVE-1111-1", "golang.org/x/text", sarif.ReachabilityReachable)
	b := analyzed("repo-a", "CVE-2222-2", "lodash", sarif.ReachabilityUnreachable)
	b.Tool = "dep-scan"
	b.Reachability.Analyzer = "dep-scan"
	ctrls := controlsWith(
		scanned("repo-a", "CVE-1111-1", "golang.org/x/text"),
		scanned("repo-a", "CVE-2222-2", "lodash"),
		a, b,
	)
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})

	if len(got.Analyzers) != 2 {
		t.Fatalf("analyzers = %+v, want both", got.Analyzers)
	}
	if got.Analyzers[0].Analyzer != "dep-scan" || got.Analyzers[1].Analyzer != "govulncheck" {
		t.Errorf("analyzers not in name order: %+v", got.Analyzers)
	}
	if got.Analyzers[0].Unreachable != 1 || got.Analyzers[1].Reachable != 1 {
		t.Errorf("counts landed on the wrong analyzer: %+v", got.Analyzers)
	}
	if got.Reachable != 1 || got.Unreachable != 1 {
		t.Errorf("totals = %+v", got)
	}
}

func TestApplyReachabilityTakesTheStrongerVerdictWhenAnalyzersDisagree(t *testing.T) {
	// Two analyzers covering the same dependency and disagreeing means one found a path the
	// other could not follow. Failing to find something is much weaker evidence than finding it,
	// so the stronger claim of exposure wins, the direction every conflict here resolves in.
	weak := analyzed("repo-a", "CVE-1111-1", "m", sarif.ReachabilityUnreachable)
	weak.Tool = "dep-scan"
	weak.Reachability.Analyzer = "dep-scan"
	strong := analyzed("repo-a", "CVE-1111-1", "m", sarif.ReachabilityReachable)

	for _, order := range [][]sarif.Result{{weak, strong}, {strong, weak}} {
		ctrls := controlsWith(append([]sarif.Result{scanned("repo-a", "CVE-1111-1", "m")}, order...)...)
		e := &Engine{}
		e.applyReachability(ctrls, saga.Model{})
		var got sarif.ReachabilityState
		for _, r := range ctrls["sca"].Report.Results {
			if r.Tool == "trivy" && r.Reachability != nil {
				got = r.Reachability.State
			}
		}
		if got != sarif.ReachabilityReachable {
			t.Errorf("state = %q, want reachable whichever analyzer was indexed first", got)
		}
	}
}

// in places a finding in a manifest, the way the scanners report one Go module among several.
func in(res sarif.Result, manifest string) sarif.Result {
	res.Location.URI = manifest
	return res
}

func TestApplyReachabilityDoesNotCollapseModules(t *testing.T) {
	// One repository, two Go modules requiring the same dependency. The module that calls the
	// vulnerable function is reachable; the one that only requires it is not, and must not be
	// lent the other's verdict and call path.
	ctrls := controlsWith(
		in(scanned("repo", "CVE-2020-36067", "github.com/tidwall/gjson"), "go.mod"),
		in(scanned("repo", "CVE-2020-36067", "github.com/tidwall/gjson"), "tools/go.mod"),
		in(analyzed("repo", "CVE-2020-36067", "github.com/tidwall/gjson", sarif.ReachabilityReachable), "go.mod"),
		in(analyzed("repo", "CVE-2020-36067", "github.com/tidwall/gjson", sarif.ReachabilityUnreachable), "tools/go.mod"),
	)
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})

	byManifest := map[string]sarif.ReachabilityState{}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Tool != "trivy" {
			t.Errorf("an analyzer finding was kept beside the scanner's: %+v", r)
		}
		if r.Reachability != nil {
			byManifest[r.Location.URI] = r.Reachability.State
		}
	}
	if byManifest["go.mod"] != sarif.ReachabilityReachable || byManifest["tools/go.mod"] != sarif.ReachabilityUnreachable {
		t.Errorf("verdicts = %v, want reachable at go.mod and unreachable at tools/go.mod", byManifest)
	}
	if got.Reachable != 1 || got.Unreachable != 1 {
		t.Errorf("summary = %+v, want one of each", got)
	}
}

// of stamps a finding with the component whose job produced it.
func of(res sarif.Result, component string) sarif.Result {
	res.Component = component
	return res
}

func TestApplyReachabilityDoesNotCollapseComponentsOrModules(t *testing.T) {
	// Two components share one repository holding two Go modules, and each scans only its own
	// paths. In the root module api calls the vulnerable function and worker does not; in the
	// tools module it is the other way round. Every finding carries the verdict of its own
	// component's code in its own module, so a key missing either the component or the manifest
	// hands the reachable verdict, and a call path the finding's code does not contain, to a
	// finding that is not reachable.
	const repo, rule, pkg = "monorepo", "CVE-2020-36067", "github.com/tidwall/gjson"
	calls := map[[2]string]sarif.ReachabilityState{
		{"api", "go.mod"}:          sarif.ReachabilityReachable,
		{"api", "tools/go.mod"}:    sarif.ReachabilityUnreachable,
		{"worker", "go.mod"}:       sarif.ReachabilityUnreachable,
		{"worker", "tools/go.mod"}: sarif.ReachabilityReachable,
	}
	var results []sarif.Result
	for _, component := range []string{"api", "worker"} {
		for _, manifest := range []string{"go.mod", "tools/go.mod"} {
			state := calls[[2]string{component, manifest}]
			results = append(results,
				of(in(scanned(repo, rule, pkg), manifest), component),
				of(in(analyzed(repo, rule, pkg, state), manifest), component),
			)
		}
	}
	ctrls := controlsWith(results...)
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})

	kept := ctrls["sca"].Report.Results
	if len(kept) != len(calls) {
		t.Fatalf("results = %d, want %d, one scanner finding per component and module", len(kept), len(calls))
	}
	for _, r := range kept {
		if r.Tool != "trivy" {
			t.Errorf("an analyzer finding was kept beside the scanner's: %+v", r)
			continue
		}
		want := calls[[2]string{r.Component, r.Location.URI}]
		if r.Reachability == nil || r.Reachability.State != want {
			t.Errorf("%s at %s: verdict = %+v, want %q", r.Component, r.Location.URI, r.Reachability, want)
		}
	}
	if got.Reachable != 2 || got.Unreachable != 2 {
		t.Errorf("summary = %+v, want two reachable and two unreachable", got)
	}
}

func TestApplyReachabilityKeepsAnAnalyzerFindingNoScannerInItsComponentReported(t *testing.T) {
	// Folding is per component as well. A scanner finding in api says nothing about worker, so
	// worker's analyzer finding is the only report of the vulnerability there and must be kept,
	// and api's finding must not be given worker's verdict.
	const repo, rule, pkg = "monorepo", "CVE-2020-36067", "github.com/tidwall/gjson"
	ctrls := controlsWith(
		of(in(scanned(repo, rule, pkg), "go.mod"), "api"),
		of(in(analyzed(repo, rule, pkg, sarif.ReachabilityReachable), "go.mod"), "worker"),
	)
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})

	byComponent := map[string]sarif.Result{}
	for _, r := range ctrls["sca"].Report.Results {
		byComponent[r.Component] = r
	}
	if r := byComponent["api"]; r.Reachability != nil {
		t.Errorf("api was given another component's verdict: %+v", r.Reachability)
	}
	if r, ok := byComponent["worker"]; !ok || r.Tool != "govulncheck" {
		t.Errorf("worker's analyzer finding was folded away: %+v", ctrls["sca"].Report.Results)
	}
	if len(got.Analyzers) != 1 || got.Analyzers[0].Contributed != 1 {
		t.Errorf("summary = %+v, want the worker finding counted as contributed", got)
	}
}
