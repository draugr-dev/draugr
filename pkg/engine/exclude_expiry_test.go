package engine

import (
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func excludeFixture() map[string]plugin.ControlResult {
	return map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Location: sarif.Location{URI: "go.mod"}},
		}}},
	}
}

// The point of an expiry: past the date the finding comes back, so "until the upstream fix lands"
// cannot quietly mean forever.
func TestExpiredExclusionStopsSuppressing(t *testing.T) {
	t.Parallel()

	rule := saga.ExcludeRule{
		Rules: []string{"CVE-1"}, Reason: "upstream fix due in August",
		AcceptedBy: "Wilson Santos", Expires: "2026-08-14",
	}
	now, _ := time.Parse("2006-01-02", "2026-09-01")

	ctrls := excludeFixture()
	n, lapsed, _ := applyExclusions(ctrls, []saga.ExcludeRule{rule}, now)
	if n != 0 {
		t.Errorf("an expired exclusion suppressed %d finding(s)", n)
	}
	if ctrls["sca"].Report.Results[0].Suppressed() {
		t.Error("the finding should be back")
	}
	// Reported, not silently dropped: a finding that used to be accepted reappearing with no
	// explanation is the confusing half of expiry.
	if len(lapsed) != 1 || lapsed[0].Expires != "2026-08-14" {
		t.Errorf("lapsed = %+v, want the expired rule", lapsed)
	}

	// Before the date it still applies, and carries who accepted it.
	before, _ := time.Parse("2006-01-02", "2026-08-01")
	ctrls = excludeFixture()
	n, lapsed, _ = applyExclusions(ctrls, []saga.ExcludeRule{rule}, before)
	if n != 1 || len(lapsed) != 0 {
		t.Fatalf("suppressed=%d lapsed=%d, want 1 and 0", n, len(lapsed))
	}
	sup := ctrls["sca"].Report.Results[0].Suppression
	if sup.AcceptedBy != "Wilson Santos" || sup.Expires != "2026-08-14" {
		t.Errorf("suppression = %+v, want who and until when", sup)
	}
}

// An exclusion with no owner still works — the gap is reported rather than enforced — but the
// suppression records that nobody was named.
func TestUnattributedSuppressionIsStillRecorded(t *testing.T) {
	t.Parallel()

	ctrls := excludeFixture()
	n, _, _ := applyExclusions(ctrls,
		[]saga.ExcludeRule{{Rules: []string{"CVE-1"}, Reason: "fixture"}}, time.Now())
	if n != 1 {
		t.Fatalf("suppressed %d, want 1", n)
	}
	if got := ctrls["sca"].Report.Results[0].Suppression.AcceptedBy; got != "" {
		t.Errorf("acceptedBy = %q, want empty", got)
	}
}
