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
	const cve = "CVE-2026-78663"
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
