package engine

import (
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func controlsWith(results ...sarif.Result) map[string]plugin.ControlResult {
	rep := sarif.Report{Tool: "t", Results: results}
	c := rep.Counts()
	return map[string]plugin.ControlResult{"sca": {
		Control: "sca", Report: rep,
		Summary: plugin.Summary{Errors: c.Error, Warnings: c.Warning, Notes: c.Note},
	}}
}

func TestApplyExclusionsSuppressesRatherThanDeletes(t *testing.T) {
	// The whole point: the finding survives, carrying why it was set aside. Deleting it would
	// leave no trace that anything had been excluded.
	ctrls := controlsWith(
		sarif.Result{RuleID: "private-key", Level: sarif.LevelError, Location: sarif.Location{URI: "test/fixture.go"}},
		sarif.Result{RuleID: "aws-key", Level: sarif.LevelError, Location: sarif.Location{URI: "src/real.go"}},
	)
	n, _, _ := applyExclusions(ctrls, []saga.ExcludeRule{
		{Paths: []string{"test/fixture.go"}, Rules: []string{"private-key"}, Reason: "deliberate test fixture"},
	}, time.Now())
	if n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
	res := ctrls["sca"].Report.Results
	if len(res) != 2 {
		t.Fatalf("results = %d, want both kept", len(res))
	}
	if !res[0].Suppressed() {
		t.Error("the matched finding should be suppressed")
	}
	if res[0].Suppression.Justification != "deliberate test fixture" {
		t.Errorf("justification = %q, want the Saga's reason", res[0].Suppression.Justification)
	}
	if res[0].Suppression.Kind != "external" {
		t.Errorf("kind = %q, want external — the decision came from the Saga", res[0].Suppression.Kind)
	}
	if res[1].Suppressed() {
		t.Error("the unmatched finding must be untouched")
	}
}

func TestApplyExclusionsRemovesTheFindingFromTheVerdict(t *testing.T) {
	// Suppressing without recomputing the summary would leave the finding counted — the gate
	// would still fail on something the Saga said to set aside.
	ctrls := controlsWith(
		sarif.Result{RuleID: "k", Level: sarif.LevelError, Location: sarif.Location{URI: "test/f.go"}},
		sarif.Result{RuleID: "j", Level: sarif.LevelWarning, Location: sarif.Location{URI: "src/f.go"}},
	)
	if got := ctrls["sca"].Summary.Errors; got != 1 {
		t.Fatalf("precondition: errors = %d, want 1", got)
	}
	applyExclusions(ctrls, []saga.ExcludeRule{{Paths: []string{"test/"}, Reason: "fixtures"}}, time.Now())
	sum := ctrls["sca"].Summary
	if sum.Errors != 0 {
		t.Errorf("errors = %d, want 0 after suppression", sum.Errors)
	}
	if sum.Warnings != 1 {
		t.Errorf("warnings = %d, want the unsuppressed one still counted", sum.Warnings)
	}
	if c := ctrls["sca"].Report.Counts(); c.Error != 0 {
		t.Errorf("Counts still sees the suppressed error: %+v", c)
	}
}

func TestApplyExclusionsNoRulesIsANoop(t *testing.T) {
	ctrls := controlsWith(sarif.Result{RuleID: "k", Level: sarif.LevelError, Location: sarif.Location{URI: "a.go"}})
	if n, _, _ := applyExclusions(ctrls, nil, time.Now()); n != 0 {
		t.Errorf("suppressed = %d, want 0", n)
	}
	if ctrls["sca"].Report.Results[0].Suppressed() {
		t.Error("nothing should be suppressed without rules")
	}
}

func TestApplyExclusionsLeavesAnUpstreamSuppressionAlone(t *testing.T) {
	// A scanner may already have suppressed a result for its own reason. Overwriting that with
	// ours would lose the original justification and double-count the suppression.
	ctrls := controlsWith(sarif.Result{
		RuleID: "k", Level: sarif.LevelError, Location: sarif.Location{URI: "a.go"},
		Suppression: &sarif.Suppression{Kind: "inSource", Justification: "nosem comment"},
	})
	if n, _, _ := applyExclusions(ctrls, []saga.ExcludeRule{{Paths: []string{"*.go"}, Reason: "ours"}}, time.Now()); n != 0 {
		t.Errorf("suppressed = %d, want 0 — it was already suppressed", n)
	}
	if got := ctrls["sca"].Report.Results[0].Suppression.Justification; got != "nosem comment" {
		t.Errorf("justification = %q, want the original preserved", got)
	}
}

func TestApplyExclusionsFirstMatchWins(t *testing.T) {
	// Two rules can cover the same finding. It is suppressed once, with the first reason, so
	// the count matches the number of findings rather than the number of matches.
	ctrls := controlsWith(sarif.Result{RuleID: "k", Level: sarif.LevelError, Location: sarif.Location{URI: "test/f.go"}})
	n, _, _ := applyExclusions(ctrls, []saga.ExcludeRule{
		{Paths: []string{"test/"}, Reason: "first"},
		{Rules: []string{"k"}, Reason: "second"},
	}, time.Now())
	if n != 1 {
		t.Errorf("suppressed = %d, want 1", n)
	}
	if got := ctrls["sca"].Report.Results[0].Suppression.Justification; got != "first" {
		t.Errorf("justification = %q, want %q", got, "first")
	}
}

func TestApplyExclusionsCountsWhatABroadGlobSwallowed(t *testing.T) {
	// Wildcards in `rules` are only safe because a wide pattern is loud. Nothing is deleted:
	// the count is reported and every suppressed finding stays in the report carrying the
	// justification. This test is the reason globs were acceptable at all — if suppression
	// were silent, `*` would be a way to make a security control disappear.
	ctrls := controlsWith(
		sarif.Result{RuleID: "license/MIT/a", Level: sarif.LevelWarning, Location: sarif.Location{URI: "go.mod"}},
		sarif.Result{RuleID: "license/MIT/b", Level: sarif.LevelWarning, Location: sarif.Location{URI: "go.mod"}},
		sarif.Result{RuleID: "license/GPL-3.0-only/c", Level: sarif.LevelError, Location: sarif.Location{URI: "go.mod"}},
		sarif.Result{RuleID: "CVE-2019-1", Level: sarif.LevelError, Location: sarif.Location{URI: "go.mod"}},
	)
	n, _, _ := applyExclusions(ctrls, []saga.ExcludeRule{
		{Rules: []string{"license/*"}, Reason: "licence policy handled out of band"},
	}, time.Now())
	if n != 3 {
		t.Fatalf("suppressed = %d, want all three licence findings", n)
	}
	res := ctrls["sca"].Report.Results
	for i := range res[:3] {
		if !res[i].Suppressed() {
			t.Errorf("result %d should be suppressed by the glob", i)
		}
	}
	// The CVE is not a licence finding and must survive an unrelated pattern.
	if res[3].Suppressed() {
		t.Error("license/* must not sweep up a CVE")
	}
	// And the verdict still sees the CVE.
	if c := ctrls["sca"].Report.Counts(); c.Error != 1 {
		t.Errorf("Counts = %+v, want the unsuppressed error still counted", c)
	}
}

func TestApplyExclusionsGlobMatchesAcrossSeparators(t *testing.T) {
	// The case the whole design turned on: package names contain slashes, so a wildcard that
	// stopped at "/" could not express "this licence, whichever package".
	ctrls := controlsWith(sarif.Result{
		RuleID: "license/GPL-3.0-only/github.com/somelib/thing",
		Level:  sarif.LevelWarning, Location: sarif.Location{URI: "go.mod"},
	})
	if n, _, _ := applyExclusions(ctrls, []saga.ExcludeRule{
		{Rules: []string{"license/GPL-3.0-only/*"}, Reason: "legal reviewed; we don't distribute"},
	}, time.Now()); n != 1 {
		t.Errorf("suppressed = %d, want the compound id matched", n)
	}
}

func TestApplyExclusionsReportsARuleThatMatchedNothing(t *testing.T) {
	// An exclusion doing nothing reads exactly like one that is working. Usually a typo, a rule
	// id that moved, or a finding someone fixed and forgot to stop excusing — and in every case
	// the descriptor claims a decision it is not making.
	ctrls := controlsWith(
		sarif.Result{RuleID: "draugr/cis/5.1.1", Level: sarif.LevelError, Location: sarif.Location{URI: "cluster"}},
	)
	_, _, unmatched := applyExclusions(ctrls, []saga.ExcludeRule{
		{Rules: []string{"draugr/cis/5.1.1"}, Reason: "accepted"},
		{Rules: []string{"cis/5.1.1"}, Reason: "written before the ids were namespaced"},
		{Paths: []string{"nowhere/"}, Reason: "a directory that no longer exists"},
	}, time.Now())

	if len(unmatched) != 2 {
		t.Fatalf("unmatched = %d, want the two that matched nothing", len(unmatched))
	}
	if unmatched[0].Reason != "written before the ids were namespaced" {
		t.Errorf("order should follow the descriptor: %+v", unmatched)
	}
}

func TestApplyExclusionsCountsAnExpiredRuleAsLapsedNotUnmatched(t *testing.T) {
	// A rule that expired did not fail to match; it was withdrawn before matching was attempted,
	// and reporting it twice would say two different things happened.
	ctrls := controlsWith(sarif.Result{RuleID: "x", Level: sarif.LevelError})
	_, lapsed, unmatched := applyExclusions(ctrls, []saga.ExcludeRule{
		{Rules: []string{"x"}, Reason: "accepted", Expires: "2000-01-01"},
	}, time.Now())
	if len(lapsed) != 1 {
		t.Errorf("lapsed = %d, want 1", len(lapsed))
	}
	if len(unmatched) != 0 {
		t.Errorf("an expired rule is not an unmatched one: %+v", unmatched)
	}
}
