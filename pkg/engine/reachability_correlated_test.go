package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// xnet is golang.org/x/net as a manifest scanner reports it in one component's go.mod.
func xnet(tool, rule, component, repo string, level sarif.Level) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: level, Component: component, Repository: repo,
		Location: sarif.Location{URI: "go.mod"},
		Package: &sarif.Package{
			Name: "golang.org/x/net", Version: "v0.57.0", Ecosystem: "gomod",
			PURL: "pkg:golang/golang.org/x/net@v0.57.0",
		},
	}
}

// Trivy and Grype report one advisory under their own rule ids, Grype's carrying the package, and
// govulncheck rules it unreachable in one component. Every copy there carries the verdict and the
// band it moves to, so whichever copy correlation counts is ranked by it. The other component,
// where nothing ruled, keeps no verdict: the same advisory in another repository is another
// finding. And the summary counts each flaw once, as the bands do.
func TestAVerdictReachesEveryScannersCopyOfTheFlaw(t *testing.T) {
	verdictReachesEveryCopy(t, "CVE-2026-78663")
}

// The same holds for a flaw with no CVE, which every scanner, govulncheck included, reports under
// its GitHub advisory id.
func TestAVerdictReachesEveryScannersCopyOfAFlawWithNoCVE(t *testing.T) {
	verdictReachesEveryCopy(t, "GHSA-w67g-5rqw-f597")
}

// verdictReachesEveryCopy runs the case above for the advisory id cve.
func verdictReachesEveryCopy(t *testing.T, cve string) {
	t.Helper()
	verdict := analyzed("repo-api", cve, "golang.org/x/net", sarif.ReachabilityUnreachable)
	verdict.Location = sarif.Location{URI: "go.mod"}
	ctrls := controlsWith(
		xnet("trivy", cve, "api", "repo-api", sarif.LevelWarning),
		xnet("grype", cve+"-golang.org/x/net", "api", "repo-api", sarif.LevelError),
		verdict,
		xnet("trivy", cve, "web", "repo-web", sarif.LevelWarning),
		xnet("grype", cve+"-golang.org/x/net", "web", "repo-web", sarif.LevelError),
	)
	for i := range ctrls["sca"].Report.Results {
		ctrls["sca"].Report.Results[i].Priority = "P1"
	}
	e := &Engine{prioritize: func(_ string, _ saga.Exposure, _ saga.Criticality, res sarif.Result) Priority {
		if res.Reachability != nil && res.Reachability.State == sarif.ReachabilityUnreachable {
			return Priority{Band: "P2"}
		}
		return Priority{Band: "P1"}
	}}

	summary := e.applyReachability(ctrls, saga.Model{})
	applyCorrelation(ctrls)
	summary = recountReachability(ctrls, summary)

	results := ctrls["sca"].Report.Results
	if len(results) != 4 {
		t.Fatalf("results = %d, want 4: govulncheck's copy folds onto the scanners' findings", len(results))
	}
	counted := 0
	for _, res := range results {
		switch res.Component {
		case "api":
			if res.Reachability == nil || res.Reachability.State != sarif.ReachabilityUnreachable {
				t.Errorf("%s %s in api has verdict %+v, want unreachable", res.Tool, res.RuleID, res.Reachability)
			}
			if res.Priority != "P2" {
				t.Errorf("%s %s in api is %s, want P2, the band its verdict sets", res.Tool, res.RuleID, res.Priority)
			}
			if !res.Correlated() {
				counted++
			}
		case "web":
			if res.Reachability != nil {
				t.Errorf("%s %s in web took a verdict ruled in api: %+v", res.Tool, res.RuleID, res.Reachability)
			}
		}
	}
	if counted != 1 {
		t.Errorf("api counts %d copies of the flaw, want 1", counted)
	}
	if summary.Unreachable != 1 || len(summary.Analyzers) != 1 || summary.Analyzers[0].Unreachable != 1 {
		t.Errorf("summary = %+v, want one unreachable flaw from govulncheck", summary)
	}
}

// Two Go modules in one component require gjson, and the analyzer finds the vulnerable call in one of
// them. Correlation counts the two as one flaw, and each module's finding keeps its own verdict and
// the band that verdict sets: the copy is still the record of its own module, and the fix list
// names its file.
func TestEachModuleKeepsItsVerdictThroughCorrelation(t *testing.T) {
	const repo, rule, pkg = "repo", "CVE-2020-36067", "github.com/tidwall/gjson"
	withPURL := func(r sarif.Result) sarif.Result {
		r.Package.PURL = "pkg:golang/" + pkg + "@v0.3.0"
		return r
	}
	ctrls := controlsWith(
		withPURL(in(scanned(repo, rule, pkg), "go.mod")),
		withPURL(in(scanned(repo, rule, pkg), "tools/go.mod")),
		in(analyzed(repo, rule, pkg, sarif.ReachabilityReachable), "go.mod"),
		in(analyzed(repo, rule, pkg, sarif.ReachabilityUnreachable), "tools/go.mod"),
	)
	e := &Engine{prioritize: func(_ string, _ saga.Exposure, _ saga.Criticality, res sarif.Result) Priority {
		if res.Reachability != nil && res.Reachability.State == sarif.ReachabilityUnreachable {
			return Priority{Band: "P2"}
		}
		return Priority{Band: "P1"}
	}}
	e.applyReachability(ctrls, saga.Model{})
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want the two modules' findings correlated as one flaw", groups)
	}

	want := map[string]struct {
		state sarif.ReachabilityState
		band  string
	}{
		"go.mod":       {sarif.ReachabilityReachable, "P1"},
		"tools/go.mod": {sarif.ReachabilityUnreachable, "P2"},
	}
	results := ctrls["sca"].Report.Results
	if len(results) != len(want) {
		t.Fatalf("results = %d, want one per module", len(results))
	}
	for _, r := range results {
		w := want[r.Location.URI]
		if r.Reachability == nil || r.Reachability.State != w.state || r.Priority != w.band {
			t.Errorf("%s: verdict %+v at %s, want %s at %s", r.Location.URI, r.Reachability, r.Priority, w.state, w.band)
		}
	}
}

// moduleFlaw is one advisory in golang.org/x/net as Trivy reports it in one Go module, and the
// analyzer's verdict on the same module.
func moduleFlaw(component, repo, manifest string, state sarif.ReachabilityState) (scanner, verdict sarif.Result) {
	scanner = xnet("trivy", "CVE-2026-78663", component, repo, sarif.LevelWarning)
	scanner.Location = sarif.Location{URI: manifest}
	verdict = in(analyzed(repo, "CVE-2026-78663", "golang.org/x/net", state), manifest)
	verdict.Component = component
	return scanner, verdict
}

// bandByVerdict is a prioritizer that ranks an unreachable finding one severity level down.
func bandByVerdict(_ string, _ saga.Exposure, _ saga.Criticality, res sarif.Result) Priority {
	if res.Reachability != nil && res.Reachability.State == sarif.ReachabilityUnreachable {
		return Priority{Band: "P2"}
	}
	return Priority{Band: "P1"}
}

// One scanner reports the flaw in two Go modules of api: go.mod calls the vulnerable function and
// tools/go.mod only requires it. Correlation makes the two one flaw, and the copy it counts is the
// reachable P1 one in either result order, so the bands, the fix list and the gate read P1. The
// unreachable copy keeps its own P2 as evidence. web holds only the unreachable module, in another
// repository, and keeps its own P2, counted in its own right.
func TestCorrelationCountsTheMostExposedModule(t *testing.T) {
	mainMod, mainVerdict := moduleFlaw("api", "repo-api", "go.mod", sarif.ReachabilityReachable)
	toolsMod, toolsVerdict := moduleFlaw("api", "repo-api", "tools/go.mod", sarif.ReachabilityUnreachable)
	webMod, webVerdict := moduleFlaw("web", "repo-web", "tools/go.mod", sarif.ReachabilityUnreachable)
	for _, order := range []struct {
		name    string
		results []sarif.Result
	}{
		{"go.mod first", []sarif.Result{mainMod, toolsMod, webMod, mainVerdict, toolsVerdict, webVerdict}},
		{"tools/go.mod first", []sarif.Result{toolsVerdict, webVerdict, mainVerdict, webMod, toolsMod, mainMod}},
	} {
		t.Run(order.name, func(t *testing.T) {
			ctrls := controlsWith(order.results...)
			e := &Engine{prioritize: bandByVerdict}
			summary := e.applyReachability(ctrls, saga.Model{})
			if groups, _ := applyCorrelation(ctrls); groups != 1 {
				t.Fatalf("groups = %d, want api's two modules as one flaw", groups)
			}
			summary = recountReachability(ctrls, summary)

			type where struct{ component, manifest string }
			want := map[where]struct {
				band    string
				counted bool
			}{
				{"api", "go.mod"}:       {"P1", true},
				{"api", "tools/go.mod"}: {"P2", false},
				{"web", "tools/go.mod"}: {"P2", true},
			}
			got := ctrls["sca"].Report.Results
			if len(got) != len(want) {
				t.Fatalf("results = %d, want one per module: the analyzer's copies fold", len(got))
			}
			for _, r := range got {
				w := want[where{r.Component, r.Location.URI}]
				if r.Priority != w.band {
					t.Errorf("%s %s is %s, want %s, the band its own verdict sets", r.Component, r.Location.URI, r.Priority, w.band)
				}
				if counted := !r.Correlated(); counted != w.counted {
					t.Errorf("%s %s counted = %v, want %v", r.Component, r.Location.URI, counted, w.counted)
				}
			}
			if n := ctrls["sca"].Report.Counts().Total(); n != 2 {
				t.Errorf("counted %d findings, want one flaw in each component", n)
			}
			if summary.Reachable != 1 || summary.Unreachable != 1 {
				t.Errorf("summary = %+v, want api's flaw reachable and web's unreachable", summary)
			}
		})
	}
}

// Where the two modules' bands tie, the counted copy's own verdict can say less than the other's,
// as the unreachable module's does when nothing is prioritized and as a module the analyzer did not
// rule on does when both stay at P1. The flaw is reachable from go.mod in both cases, and the
// summary counts it reachable once, whichever copy carries the count.
func TestTheSummaryCountsAFlawReachableIfAnyModuleReachesIt(t *testing.T) {
	mainMod, mainVerdict := moduleFlaw("api", "repo-api", "go.mod", sarif.ReachabilityReachable)
	toolsMod, toolsVerdict := moduleFlaw("api", "repo-api", "tools/go.mod", sarif.ReachabilityUnreachable)
	// A run stamps every finding's band before reachability, and a copy no verdict reaches keeps it,
	// so the copy is stamped here as the run would stamp it.
	stampedTools := toolsMod
	stampedTools.Priority = "P1"
	for _, c := range []struct {
		name    string
		engine  *Engine
		results []sarif.Result
	}{
		{"the unreachable module is counted", &Engine{}, []sarif.Result{toolsMod, mainMod, mainVerdict, toolsVerdict}},
		{"a module with no verdict is counted", &Engine{prioritize: bandByVerdict}, []sarif.Result{stampedTools, mainMod, mainVerdict}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctrls := controlsWith(c.results...)
			summary := c.engine.applyReachability(ctrls, saga.Model{})
			applyCorrelation(ctrls)
			summary = recountReachability(ctrls, summary)

			for _, r := range ctrls["sca"].Report.Results {
				if !r.Correlated() && r.Location.URI != "tools/go.mod" {
					t.Fatalf("counted %s; this case needs tools/go.mod counted, which the tie leaves first", r.Location.URI)
				}
			}
			if summary.Reachable != 1 || summary.Unreachable != 0 {
				t.Errorf("summary = %+v, want one reachable flaw and nothing unreachable", summary)
			}
			if len(summary.Analyzers) != 1 || summary.Analyzers[0].Reachable != 1 || summary.Analyzers[0].Unreachable != 0 {
				t.Errorf("analyzers = %+v, want govulncheck credited with one reachable flaw", summary.Analyzers)
			}
		})
	}
}

// A summary from a run where no analyzer ran is left as it is, and an analyzer that appears only
// on a finding is still counted.
func TestRecountReachability(t *testing.T) {
	if got := recountReachability(controlsWith(), ReachabilitySummary{}); got.Ran() {
		t.Errorf("a run with no analyzer gained one: %+v", got)
	}
	ctrls := controlsWith(
		analyzed("r", "CVE-1", "p", sarif.ReachabilityReachable),
		analyzed("r", "CVE-2", "p", sarif.ReachabilityUnknown),
	)
	got := recountReachability(ctrls, ReachabilitySummary{Analyzers: []AnalyzerReachability{{Analyzer: "other", Contributed: 3}}})
	if got.Reachable != 1 || got.Unknown != 1 || len(got.Analyzers) != 2 {
		t.Fatalf("summary = %+v, want 1 reachable and 1 unknown across two analyzers", got)
	}
	if got.Analyzers[1].Analyzer != "other" || got.Analyzers[1].Contributed != 3 {
		t.Errorf("an analyzer's contribution was lost: %+v", got.Analyzers)
	}
}
