package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// RankUnder ranks a finding read back from a report as the scan ranked it: given the classification
// the scan used, it returns the band the scan gave, across a control's floor, a pinned tag's cap and
// the matrices alone. A comparison that swaps in its base's classification then changes nothing else.
func TestRankUnderAgreesWithTheScan(t *testing.T) {
	floored := controllers.ControlsWithContextFloor()
	if len(floored) == 0 {
		t.Fatal("no control declares a context floor to test with")
	}
	pinned := sarif.Result{RuleID: "pin", Level: sarif.LevelError, Aside: sarif.AsidePinned}
	prioritize := PrioritizerWith(nil, nil)
	for _, tc := range []struct {
		control string
		res     sarif.Result
	}{
		{"sca", sarif.Result{RuleID: "CVE-1", Level: sarif.LevelError}},
		{"sca", sarif.Result{RuleID: "CVE-2", Level: sarif.LevelNote, Score: 9.8, HasScore: true}},
		{floored[0], sarif.Result{RuleID: "leak", Level: sarif.LevelWarning}},
		{"actions", pinned},
	} {
		for _, e := range saga.Exposures {
			for _, c := range saga.Criticalities {
				p := prioritize(tc.control, e, c, tc.res)
				read := tc.res
				read.Control, read.SeverityFloor, read.Escalation = tc.control, p.SeverityFloor, p.Escalation
				if got := RankUnder(read, e, c); got != p.Band {
					t.Errorf("%s %s on %s/%s: RankUnder = %s, the scan ranked %s", tc.control, tc.res.RuleID, e, c, got, p.Band)
				}
			}
		}
	}
}
