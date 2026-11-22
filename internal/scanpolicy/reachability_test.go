package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func bandFor(res sarif.Result, expl *exploit.Source) (string, sarif.Severity) {
	p := DefaultPrioritizer(expl)("sca", "public", "important", res)
	return p.Band, p.RankedAs
}

func TestUnreachableRanksDown(t *testing.T) {
	high := sarif.Result{RuleID: "CVE-2020-14040", Level: sarif.LevelError, Score: 7.5, HasScore: true}
	reachable := high
	reachable.Reachability = &sarif.Reachability{State: sarif.ReachabilityReachable, Method: sarif.MethodCallGraph}
	unreachable := high
	unreachable.Reachability = &sarif.Reachability{State: sarif.ReachabilityUnreachable, Method: sarif.MethodCallGraph}

	reachBand, reachRanked := bandFor(reachable, nil)
	unreachBand, unreachRanked := bandFor(unreachable, nil)

	if reachBand == unreachBand {
		t.Errorf("both banded %q, reachability changed nothing", reachBand)
	}
	if reachRanked != "" {
		t.Errorf("reachable recorded rankedAs %q; severity already assumes the code runs", reachRanked)
	}
	if unreachRanked != sarif.SeverityMedium {
		t.Errorf("unreachable rankedAs = %q, want medium", unreachRanked)
	}
}

func TestAWeakMethodDoesNotMoveTheBand(t *testing.T) {
	// The verdict still travels and is still shown. What it does not do is move the band, because
	// the reader deciding whether to act on it has to make that call rather than have it made by a
	// framework's own account of which handlers are wired.
	res := sarif.Result{
		RuleID: "CVE-2020-14040", Level: sarif.LevelError, Score: 7.5, HasScore: true,
		Reachability: &sarif.Reachability{
			State: sarif.ReachabilityUnreachable, Method: sarif.MethodFrameworkHeuristic,
		},
	}
	band, ranked := bandFor(res, nil)
	if ranked != "" {
		t.Errorf("a framework heuristic recorded rankedAs %q", ranked)
	}
	strong := res
	strong.Reachability = &sarif.Reachability{
		State: sarif.ReachabilityUnreachable, Method: sarif.MethodCallGraph,
	}
	if strongBand, _ := bandFor(strong, nil); strongBand == band {
		t.Errorf("both banded %q; the method changed nothing", band)
	}
}

func TestExploitabilityOutranksReachability(t *testing.T) {
	// Observed exploitation outranks a call graph's inability to find a path. The same rule that
	// makes KEV outrank EPSS. Where both speak, the stronger claim of exposure wins.
	kev := exploit.New(map[string]bool{"CVE-2020-14040": true}, nil, 0)
	res := sarif.Result{
		RuleID: "CVE-2020-14040", Level: sarif.LevelError, Score: 7.5, HasScore: true,
		Reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable, Method: sarif.MethodCallGraph},
	}
	band, ranked := bandFor(res, kev)
	if ranked != "" {
		t.Errorf("rankedAs = %q, an escalated finding must not be lowered", ranked)
	}
	escalatedOnly := res
	escalatedOnly.Reachability = nil
	wantBand, _ := bandFor(escalatedOnly, kev)
	if band != wantBand {
		t.Errorf("band = %q, want %q, reachability changed an escalated finding", band, wantBand)
	}
}

func TestNoReachabilityIsANoop(t *testing.T) {
	res := sarif.Result{RuleID: "CVE-2020-14040", Level: sarif.LevelError, Score: 7.5, HasScore: true}
	if _, ranked := bandFor(res, nil); ranked != "" {
		t.Errorf("rankedAs = %q, want empty when nothing analyzed", ranked)
	}
}
