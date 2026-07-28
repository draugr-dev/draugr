package engine

import (
	"testing"

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
	n := applyExclusions(ctrls, []saga.ExcludeRule{
		{Paths: []string{"test/fixture.go"}, Rules: []string{"private-key"}, Reason: "deliberate test fixture"},
	})
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
	applyExclusions(ctrls, []saga.ExcludeRule{{Paths: []string{"test/"}, Reason: "fixtures"}})
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
	if n := applyExclusions(ctrls, nil); n != 0 {
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
	if n := applyExclusions(ctrls, []saga.ExcludeRule{{Paths: []string{"*.go"}, Reason: "ours"}}); n != 0 {
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
	n := applyExclusions(ctrls, []saga.ExcludeRule{
		{Paths: []string{"test/"}, Reason: "first"},
		{Rules: []string{"k"}, Reason: "second"},
	})
	if n != 1 {
		t.Errorf("suppressed = %d, want 1", n)
	}
	if got := ctrls["sca"].Report.Results[0].Suppression.Justification; got != "first" {
		t.Errorf("justification = %q, want %q", got, "first")
	}
}
