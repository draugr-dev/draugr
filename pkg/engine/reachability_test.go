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
		t.Fatalf("results = %d, want 1 — the analyzer's copy should fold away", len(res))
	}
	if res[0].Tool != "trivy" {
		t.Errorf("kept tool = %q, want the scanner that rated it", res[0].Tool)
	}
	if res[0].Reachability == nil || res[0].Reachability.State != sarif.ReachabilityReachable {
		t.Fatalf("verdict did not move onto the finding: %+v", res[0].Reachability)
	}
	if got.Reachable != 1 || got.Analyzer != "govulncheck" {
		t.Errorf("summary = %+v, want 1 reachable from govulncheck", got)
	}
}

func TestApplyReachabilityKeepsWhatNothingElseReported(t *testing.T) {
	// A vulnerability only one tool found is exactly the one that must not disappear in a
	// deduplication — the Go standard library is the case that produces it.
	ctrls := controlsWith(
		analyzed("repo-a", "CVE-2024-24790", "stdlib", sarif.ReachabilityReachable),
	)
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})

	if n := len(ctrls["sca"].Report.Results); n != 1 {
		t.Fatalf("results = %d, want the unmatched finding kept", n)
	}
	if got.Contributed != 1 {
		t.Errorf("contributed = %d, want 1", got.Contributed)
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
	// and the reported severity does not — and the finding says which severity it was ranked at.
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
		t.Errorf("priority = %q, want P2 — the band should have moved", res.Priority)
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
		t.Errorf("both findings recorded %q — the verdict was shared, not copied", got["CVE-1111-1"])
	}
}

func TestApplyReachabilityNoAnalyzerIsANoop(t *testing.T) {
	ctrls := controlsWith(scanned("repo-a", "CVE-2022-32149", "golang.org/x/text"))
	e := &Engine{}
	got := e.applyReachability(ctrls, saga.Model{})
	if got.Analyzer != "" || got.Reachable+got.Unreachable+got.Unknown != 0 {
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
