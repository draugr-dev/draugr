package report

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Within a band, a finding a call path reaches comes before the rest. An unreachable verdict and a
// not-built mark rank as no answer, since each covers only the builds analyzed, so the unreachable
// critical here keeps its place by severity and score, ahead of the highs. The band still comes
// first.
func TestTheFindingsListRanksReachabilityWithinABand(t *testing.T) {
	unreachable := finding{priority: "P1", severity: sarif.SeverityCritical, score: 9.1, location: "unreachable",
		reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable, Method: sarif.MethodCallGraph}}
	reachable := finding{priority: "P1", severity: sarif.SeverityHigh, score: 8.1, location: "reachable",
		reachability: &sarif.Reachability{State: sarif.ReachabilityReachable}}
	none := finding{priority: "P1", severity: sarif.SeverityHigh, score: 8.5, location: "none"}
	notBuilt := finding{priority: "P1", severity: sarif.SeverityHigh, score: 8.4, location: "not-built",
		reachability: &sarif.Reachability{State: sarif.ReachabilityNotBuilt, Method: sarif.MethodNotBuilt}}
	p2 := finding{priority: "P2", severity: sarif.SeverityHigh, score: 8.9, location: "p2",
		reachability: &sarif.Reachability{State: sarif.ReachabilityReachable}}

	fs := []finding{p2, unreachable, notBuilt, none, reachable}
	sortFindings(fs)
	var got []string
	for _, f := range fs {
		got = append(got, f.location)
	}
	want := []string{"reachable", "unreachable", "none", "not-built", "p2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// The fix list orders its actions the same way: an action clearing a finding something reaches
// comes before one clearing only a finding with an unreachable verdict, which ranks as no answer, in
// the same band, though the second finding's score is higher.
func TestTheFixListRanksReachabilityWithinABand(t *testing.T) {
	unreachable := finding{priority: "P1", severity: sarif.SeverityHigh, score: 9.1, location: "u",
		reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable, Method: sarif.MethodCallGraph}}
	reachable := finding{priority: "P1", severity: sarif.SeverityHigh, score: 8.1, location: "r",
		reachability: &sarif.Reachability{State: sarif.ReachabilityReachable}}
	actions := []action{
		{key: "lowered", priority: "P1", findings: []finding{unreachable}},
		{key: "reached", priority: "P1", findings: []finding{reachable}},
	}
	rankByPackage(actions)
	if actions[1].rank.reach != 2 || actions[0].rank.reach != 1 {
		t.Fatalf("reach = %d and %d, want 2 for the reached action and 1 for the unreachable one",
			actions[1].rank.reach, actions[0].rank.reach)
	}
	if !moreUrgent(actions[1], actions[0]) || moreUrgent(actions[0], actions[1]) {
		t.Errorf("the action clearing a reachable finding does not lead the one clearing an unreachable one")
	}
	if reachabilityOrder(finding{reachability: &sarif.Reachability{State: sarif.ReachabilityUnknown}}) != 1 {
		t.Errorf("an unknown verdict should rank as no answer")
	}
}
