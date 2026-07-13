// Package norn evaluates scan results against policy to produce a verdict
// (pass/fail) per control and overall. It begins with declarative severity thresholds;
// a richer policy language (e.g. OPA/Rego) can follow.
//
// The Norns decide fate — here, the fate of a release.
package norn

import (
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Verdict is the outcome of a policy evaluation.
type Verdict string

// The possible verdicts.
const (
	Pass Verdict = "pass"
	Fail Verdict = "fail"
)

// Policy decides verdicts from findings. A control fails when its most severe finding is
// at least as severe as the applicable threshold. FailOn is the default threshold;
// PerControl overrides it for named controls. The zero value fails on error.
//
// FailOnPriority adds component-aware gating: when set (e.g. "P1"), a control also fails if
// any of its findings has a priority band at least that urgent. Because a finding's priority
// already combines its severity with its component's exposure and criticality, this gates
// per component without a separate per-component threshold.
type Policy struct {
	FailOn         sarif.Level
	PerControl     map[string]sarif.Level
	FailOnPriority string
}

// thresholdFor returns the effective failure threshold for a control.
func (p Policy) thresholdFor(control string) sarif.Level {
	if lvl, ok := p.PerControl[control]; ok && lvl != "" {
		return lvl
	}
	if p.FailOn != "" {
		return p.FailOn
	}
	return sarif.LevelError
}

// ControlOutcome is the verdict for a single control.
type ControlOutcome struct {
	Control         string
	Verdict         Verdict
	Highest         sarif.Level
	HighestPriority string
	Counts          sarif.Counts
	Threshold       sarif.Level
}

// Result is the overall evaluation across all controls.
type Result struct {
	Verdict  Verdict
	Controls []ControlOutcome
}

// Evaluate judges each control's report against the policy and combines them. The overall
// verdict is Fail if any control fails. Controls are reported in the given order (sort
// upstream for determinism if needed).
func (p Policy) Evaluate(reports map[string]sarif.Report) Result {
	res := Result{Verdict: Pass}
	for control, report := range reports {
		threshold := p.thresholdFor(control)
		highest := report.Highest()
		highestPrio := highestPriority(report)

		outcome := ControlOutcome{
			Control:         control,
			Verdict:         Pass,
			Highest:         highest,
			HighestPriority: highestPrio,
			Counts:          report.Counts(),
			Threshold:       threshold,
		}
		// A control fails when it has a finding at or above the level threshold (LevelNone
		// has rank 0, so empty reports pass) or, when priority gating is on, a finding at or
		// above the priority threshold.
		failedOnLevel := highest.AtLeast(threshold) && highest.Rank() > 0
		if failedOnLevel || p.priorityFails(highestPrio) {
			outcome.Verdict = Fail
			res.Verdict = Fail
		}
		res.Controls = append(res.Controls, outcome)
	}
	return res
}

// priorityFails reports whether a control's most-urgent priority trips the priority gate.
func (p Policy) priorityFails(highestPrio string) bool {
	if p.FailOnPriority == "" || highestPrio == "" {
		return false
	}
	return prioritization.Priority(highestPrio).Rank() >= prioritization.Priority(p.FailOnPriority).Rank()
}

// highestPriority returns the most urgent priority band among a report's findings, or "" if
// none are prioritized.
func highestPriority(r sarif.Report) string {
	best := ""
	bestRank := 0
	for _, res := range r.Results {
		if rank := prioritization.Priority(res.Priority).Rank(); rank > bestRank {
			bestRank, best = rank, res.Priority
		}
	}
	return best
}
