package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// chi is github.com/go-chi/chi/v5 v5.2.5 in one component's go.mod, as a scanner reports it under
// rule, naming aliases beside it.
func chi(tool, rule, component, repo string, level sarif.Level, aliases ...string) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: level, Component: component, Repository: repo, Aliases: aliases,
		Location: sarif.Location{URI: "go.mod"},
		Package: &sarif.Package{
			Name: "github.com/go-chi/chi/v5", Version: "v5.2.5", Ecosystem: "gomod",
			PURL: "pkg:golang/github.com/go-chi/chi/v5@v5.2.5",
		},
	}
}

// unreachable marks res as govulncheck's finding, ruled unreachable.
func unreachable(res sarif.Result) sarif.Result {
	res.Reachability = &sarif.Reachability{State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck", Method: "call-graph"}
	return res
}

// govulncheck reports a Go flaw with no CVE under its GitHub advisory id and names the Go id beside
// it; Grype reports the same flaw from the Go database under the Go id. In each of two components,
// the verdict reaches Grype's copy and moves its band, govulncheck's copy folds onto it, and the
// summary counts the flaw once.
func TestAVerdictReachesACopyKeyedOnTheGoIDTheAnalyzerNamed(t *testing.T) {
	const ghsa, goID = "GHSA-9g5q-2w5x-hmxf", "GO-2026-5775"
	ctrls := controlsWith(
		chi("grype", goID+"-github.com/go-chi/chi/v5", "api", "repo-api", sarif.LevelNote),
		unreachable(chi("govulncheck", ghsa, "api", "repo-api", sarif.LevelWarning, goID)),
		unreachable(chi("govulncheck", ghsa, "web", "repo-web", sarif.LevelWarning, goID)),
		chi("grype", goID+"-github.com/go-chi/chi/v5", "web", "repo-web", sarif.LevelNote),
	)
	e := &Engine{prioritize: bandByVerdict}
	summary := e.applyReachability(ctrls, saga.Model{})
	applyCorrelation(ctrls)
	summary = recountReachability(ctrls, summary)

	results := ctrls["sca"].Report.Results
	if len(results) != 2 {
		t.Fatalf("results = %d, want Grype's copy in each component: govulncheck's folds onto it", len(results))
	}
	for _, r := range results {
		if r.Tool != "grype" || r.Correlated() {
			t.Errorf("%s %s %s: want Grype's copy, counted", r.Component, r.Tool, r.RuleID)
		}
		if r.Reachability == nil || r.Reachability.State != sarif.ReachabilityUnreachable || r.Priority != "P2" {
			t.Errorf("%s %s: verdict %+v at %s, want unreachable at P2", r.Component, r.RuleID, r.Reachability, r.Priority)
		}
	}
	if summary.Unreachable != 2 || summary.Reachable+summary.Unknown != 0 {
		t.Errorf("summary = %+v, want the flaw unreachable once in each component", summary)
	}
	if len(summary.Analyzers) != 1 || summary.Analyzers[0].Contributed != 0 {
		t.Errorf("analyzers = %+v, want govulncheck contributing no finding of its own", summary.Analyzers)
	}
}

// The scanner's own aliases carry the verdict as well: Grype reports a flaw by its GitHub advisory
// id and names the CVE govulncheck reported it under.
func TestAVerdictReachesACopyThatNamesTheAnalyzersIdentifier(t *testing.T) {
	const cve, ghsa = "CVE-2026-78663", "GHSA-w67g-5rqw-f597"
	ctrls := controlsWith(
		chi("grype", ghsa+"-github.com/go-chi/chi/v5", "api", "repo-api", sarif.LevelError, cve),
		unreachable(chi("govulncheck", cve, "api", "repo-api", sarif.LevelWarning)),
	)
	(&Engine{prioritize: bandByVerdict}).applyReachability(ctrls, saga.Model{})
	results := ctrls["sca"].Report.Results
	if len(results) != 1 || results[0].Tool != "grype" {
		t.Fatalf("results = %+v, want Grype's copy alone", results)
	}
	if r := results[0]; r.Reachability == nil || r.Reachability.State != sarif.ReachabilityUnreachable || r.Priority != "P2" {
		t.Errorf("verdict %+v at %s, want unreachable at P2", r.Reachability, r.Priority)
	}
}

// govulncheck reports one Go advisory with two CVEs as two findings, each naming the other. Trivy
// reports one of them. The verdict reaches Trivy's copy through its own identifier, and
// govulncheck's finding under the other CVE stays counted: govulncheck reported the two apart.
func TestAnAnalyzersTwoFindingsAreNotFoldedThroughEachOther(t *testing.T) {
	const goID, first, second = "GO-2021-0159", "CVE-2015-5739", "CVE-2015-5740"
	ctrls := controlsWith(
		chi("trivy", first, "api", "repo-api", sarif.LevelError),
		unreachable(chi("govulncheck", first, "api", "repo-api", sarif.LevelWarning, goID, second)),
		unreachable(chi("govulncheck", second, "api", "repo-api", sarif.LevelWarning, goID, first)),
	)
	summary := (&Engine{}).applyReachability(ctrls, saga.Model{})
	got := map[string]bool{}
	for _, r := range ctrls["sca"].Report.Results {
		got[r.Tool+" "+r.RuleID] = r.Reachability != nil
	}
	want := map[string]bool{"trivy " + first: true, "govulncheck " + second: true}
	if len(got) != len(want) || !got["trivy "+first] || !got["govulncheck "+second] {
		t.Errorf("findings = %v, want %v", got, want)
	}
	if summary.Analyzers[0].Contributed != 1 {
		t.Errorf("contributed = %d, want govulncheck's finding under %s", summary.Analyzers[0].Contributed, second)
	}
}

// Where govulncheck's copy is not folded, correlation still counts the flaw once through the Go id
// it named, under the stronger reading, and the summary gives the flaw govulncheck's verdict.
func TestCorrelationJoinsAGoIDCopyThroughTheAnalyzersAlias(t *testing.T) {
	const ghsa, goID = "GHSA-9g5q-2w5x-hmxf", "GO-2026-5775"
	verdict := unreachable(chi("govulncheck", ghsa, "api", "repo-api", sarif.LevelWarning, goID))
	verdict.Priority = "P3"
	grype := chi("grype", goID+"-github.com/go-chi/chi/v5", "api", "repo-api", sarif.LevelError)
	grype.Priority = "P1"
	ctrls := controlsWith(grype, verdict)
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want the two copies joined", groups)
	}
	if got := counted(ctrls["sca"].Report.Results); len(got["api"]) != 1 || got["api"][0] != "grype "+grype.RuleID {
		t.Errorf("counted = %v, want Grype's P1 copy", got)
	}
	got := recountReachability(ctrls, ReachabilitySummary{Analyzers: []AnalyzerReachability{{Analyzer: "govulncheck"}}})
	if got.Unreachable != 1 || got.Reachable+got.Unknown != 0 {
		t.Errorf("summary = %+v, want the one flaw counted unreachable", got)
	}
}
