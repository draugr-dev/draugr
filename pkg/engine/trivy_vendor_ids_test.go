package engine

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// echo is github.com/labstack/echo/v4 v4.12.0 in one component's go.mod, with one advisory that has a
// CVE and a GitHub advisory id. Trivy keys it on the CVE and names the GitHub advisory id from its
// VendorIDs. govulncheck reads the Go database, whose entry lists the GitHub advisory id and no CVE,
// so it keys the flaw on the GitHub advisory id and names the Go id beside it.
func echo(tool, component, repo string, level sarif.Level) sarif.Result {
	const cve, ghsa, goID = "CVE-2026-118264", "GHSA-cxf3-9h37-7rr8", "GO-2026-6839"
	r := sarif.Result{
		Tool: tool, RuleID: cve, Level: level, Component: component, Repository: repo,
		Aliases:  []string{ghsa},
		Location: sarif.Location{URI: "go.mod"},
		Package: &sarif.Package{
			Name: "github.com/labstack/echo/v4", Version: "v4.12.0", Ecosystem: "gomod",
			PURL: "pkg:golang/github.com/labstack/echo/v4@v4.12.0",
		},
	}
	if tool == "govulncheck" {
		r.RuleID, r.Aliases = ghsa, []string{goID}
	}
	return r
}

// Trivy's CVE-keyed finding and govulncheck's copy keyed on the GitHub advisory id are one flaw,
// joined through the identifier Trivy named, and counted once in each of two components in two
// repositories. Without it they would be two.
func TestCorrelationJoinsTrivysCVEWithACopyKeyedOnItsGitHubAdvisoryID(t *testing.T) {
	ctrls := controlsWith(
		echo("trivy", "api", "repo-api", sarif.LevelError),
		echo("govulncheck", "api", "repo-api", sarif.LevelWarning),
		echo("trivy", "web", "repo-web", sarif.LevelError),
		echo("govulncheck", "web", "repo-web", sarif.LevelWarning),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Fatalf("groups = %d, want one flaw per component", groups)
	}
	want := map[string][]string{"api": {"trivy CVE-2026-118264"}, "web": {"trivy CVE-2026-118264"}}
	if got := counted(ctrls["sca"].Report.Results); !reflect.DeepEqual(got, want) {
		t.Errorf("counted = %v, want %v", got, want)
	}

	// The same pair with nothing named beside Trivy's CVE stays two findings.
	unnamed := echo("trivy", "api", "repo-api", sarif.LevelError)
	unnamed.Aliases = nil
	ctrls = controlsWith(unnamed, echo("govulncheck", "api", "repo-api", sarif.LevelWarning))
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none without Trivy's alias", groups)
	}
}

// govulncheck rules the flaw unreachable under the GitHub advisory id. The verdict reaches Trivy's
// CVE row through the identifier Trivy named, moving it from P1 to P2, and govulncheck's copy folds
// onto it, in each of two components in two repositories. A component whose call path govulncheck
// found keeps its row at P1, reachable.
func TestAGovulncheckVerdictReachesTrivysCVERow(t *testing.T) {
	verdict := func(res sarif.Result, state sarif.ReachabilityState) sarif.Result {
		res.Reachability = &sarif.Reachability{State: state, Analyzer: "govulncheck", Method: "call-graph"}
		return res
	}
	ctrls := controlsWith(
		echo("trivy", "api", "repo-api", sarif.LevelError),
		verdict(echo("govulncheck", "api", "repo-api", sarif.LevelWarning), sarif.ReachabilityUnreachable),
		verdict(echo("govulncheck", "web", "repo-web", sarif.LevelWarning), sarif.ReachabilityReachable),
		echo("trivy", "web", "repo-web", sarif.LevelError),
	)
	e := &Engine{prioritize: bandByVerdict}
	summary := e.applyReachability(ctrls, saga.Model{})
	applyCorrelation(ctrls)
	summary = recountReachability(ctrls, summary)

	results := ctrls["sca"].Report.Results
	if len(results) != 2 {
		t.Fatalf("results = %d, want Trivy's row in each component: govulncheck's folds onto it", len(results))
	}
	want := map[string]struct {
		state    sarif.ReachabilityState
		priority string
	}{
		"api": {sarif.ReachabilityUnreachable, "P2"},
		"web": {sarif.ReachabilityReachable, "P1"},
	}
	for _, r := range results {
		w := want[r.Component]
		if r.Tool != "trivy" || r.RuleID != "CVE-2026-118264" || r.Correlated() {
			t.Errorf("%s: %s %s, want Trivy's CVE row, counted", r.Component, r.Tool, r.RuleID)
		}
		if r.Reachability == nil || r.Reachability.State != w.state || r.Priority != w.priority {
			t.Errorf("%s: verdict %+v at %s, want %s at %s", r.Component, r.Reachability, r.Priority, w.state, w.priority)
		}
	}
	if summary.Unreachable != 1 || summary.Reachable != 1 || summary.Unknown != 0 {
		t.Errorf("summary = %+v, want the flaw unreachable in api and reachable in web", summary)
	}
	if len(summary.Analyzers) != 1 || summary.Analyzers[0].Contributed != 0 {
		t.Errorf("analyzers = %+v, want govulncheck contributing no finding of its own", summary.Analyzers)
	}
}
