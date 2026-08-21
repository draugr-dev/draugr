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
	reachable.Reachability = &sarif.Reachability{State: sarif.ReachabilityReachable}
	unreachable := high
	unreachable.Reachability = &sarif.Reachability{State: sarif.ReachabilityUnreachable}

	reachBand, reachRanked := bandFor(reachable, nil)
	unreachBand, unreachRanked := bandFor(unreachable, nil)

	if reachBand == unreachBand {
		t.Errorf("both banded %q — reachability changed nothing", reachBand)
	}
	if reachRanked != "" {
		t.Errorf("reachable recorded rankedAs %q; severity already assumes the code runs", reachRanked)
	}
	if unreachRanked != sarif.SeverityMedium {
		t.Errorf("unreachable rankedAs = %q, want medium", unreachRanked)
	}
}

func TestExploitabilityOutranksReachability(t *testing.T) {
	// Observed exploitation outranks a call graph's inability to find a path — the same rule that
	// makes KEV outrank EPSS. Where both speak, the stronger claim of exposure wins.
	kev := exploit.New(map[string]bool{"CVE-2020-14040": true}, nil, 0)
	res := sarif.Result{
		RuleID: "CVE-2020-14040", Level: sarif.LevelError, Score: 7.5, HasScore: true,
		Reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable},
	}
	band, ranked := bandFor(res, kev)
	if ranked != "" {
		t.Errorf("rankedAs = %q — an escalated finding must not be lowered", ranked)
	}
	escalatedOnly := res
	escalatedOnly.Reachability = nil
	wantBand, _ := bandFor(escalatedOnly, kev)
	if band != wantBand {
		t.Errorf("band = %q, want %q — reachability changed an escalated finding", band, wantBand)
	}
}

func TestNoReachabilityIsANoop(t *testing.T) {
	res := sarif.Result{RuleID: "CVE-2020-14040", Level: sarif.LevelError, Score: 7.5, HasScore: true}
	if _, ranked := bandFor(res, nil); ranked != "" {
		t.Errorf("rankedAs = %q, want empty when nothing analyzed", ranked)
	}
}
