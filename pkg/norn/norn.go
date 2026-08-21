// Package norn evaluates scan results against policy to produce a verdict
// (pass/fail) per control and overall. It begins with declarative severity thresholds;
// a richer policy language (e.g. OPA/Rego) can follow.
//
// The Norns decide fate — here, the fate of a release.
package norn

import (
	"sort"

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
// PerControl overrides it for named controls. The zero value fails on high.
//
// Thresholds are severity bands — the ladder the report prints — rather than SARIF levels. The
// two are not interchangeable: a finding with a CVSS score takes its band from the score, so one
// a scanner emitted as `warning` can be `high`. Gating on the level let such a finding pass a
// gate its reader believed was set to catch it, with the report beside it saying `high`.
//
// FailOnPriority adds component-aware gating: when set (e.g. "P1"), a control also fails if
// any of its findings has a priority band at least that urgent. Because a finding's priority
// already combines its severity with its component's exposure and criticality, this gates
// per component without a separate per-component threshold.
type Policy struct {
	FailOn         sarif.Severity
	PerControl     map[string]sarif.Severity
	FailOnPriority string
}

// thresholdFor returns the effective failure threshold for a control.
func (p Policy) thresholdFor(control string) sarif.Severity {
	if sev, ok := p.PerControl[control]; ok && sev != "" {
		return sev
	}
	if p.FailOn != "" {
		return p.FailOn
	}
	return sarif.SeverityHigh
}

// ControlOutcome is the verdict for a single control.
type ControlOutcome struct {
	Control         string
	Verdict         Verdict
	Highest         sarif.Severity
	HighestPriority string
	Counts          sarif.Counts
	Threshold       sarif.Severity
}

// Result is the overall evaluation across all controls.
type Result struct {
	Verdict  Verdict
	Controls []ControlOutcome
}

// Evaluate judges each control's report against the policy and combines them. The overall
// verdict is Fail if any control fails.
//
// Controls come back in **alphabetical order**, not the order the map happened to yield. Go
// randomizes map iteration, so without sorting here the same scan prints its Controls block —
// and writes its report.json, markdown and HTML — in a different order each run. That makes two
// runs of an unchanged repository diff against each other, which is the opposite of what an
// artifact offered as evidence is for, and it contradicts the promise that the same input gives
// the same answer.
//
// Alphabetical rather than, say, worst-first: it is stable as controls are added, and it matches
// how the catalog and the docs list them.
func (p Policy) Evaluate(reports map[string]sarif.Report) Result {
	res := Result{Verdict: Pass}
	for _, control := range sortedControls(reports) {
		report := reports[control]
		threshold := p.thresholdFor(control)
		highest := report.HighestSeverity()
		highestPrio := highestPriority(report)

		outcome := ControlOutcome{
			Control:         control,
			Verdict:         Pass,
			Highest:         highest,
			HighestPriority: highestPrio,
			Counts:          report.Counts(),
			Threshold:       threshold,
		}
		// A control fails when it has a finding at or above the severity threshold (an empty
		// band has rank 0, so reports with nothing to judge pass) or, when priority gating is
		// on, a finding at or above the priority threshold.
		failedOnSeverity := highest.AtLeast(threshold) && highest.Rank() > 0
		if failedOnSeverity || p.priorityFails(highestPrio) {
			outcome.Verdict = Fail
			res.Verdict = Fail
		}
		res.Controls = append(res.Controls, outcome)
	}
	return res
}

// sortedControls orders control names so a run is reproducible.
func sortedControls(reports map[string]sarif.Report) []string {
	names := make([]string, 0, len(reports))
	for name := range reports {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
		// A second scanner's copy of a flaw already counted is evidence, not a finding to gate
		// on. Counting it would let the verdict depend on how many scanners are enabled rather
		// than on what is wrong.
		if res.Correlated() {
			continue
		}
		if res.Suppressed() {
			continue // excluded by the Saga: reported, but not something to gate on
		}
		if rank := prioritization.Priority(res.Priority).Rank(); rank > bestRank {
			bestRank, best = rank, res.Priority
		}
	}
	return best
}
