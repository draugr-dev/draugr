// Package norn evaluates scan results against policy to produce a verdict
// (pass/fail) per control and overall. It begins with declarative severity thresholds;
// a richer policy language (e.g. OPA/Rego) can follow.
//
// The Norns decide fate, here, the fate of a release.
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
// PerControl overrides it for named controls.
//
// **A run has one gate.** Either it asks what a finding's own severity is, or it asks what band
// that finding lands in for this component, and those are two different questions about the same
// finding. Answering both meant a verdict had two possible reasons, and "why did this fail" could
// not be answered from the policy alone, which is how a failure on the default severity threshold
// came to be read as the priority gate somebody had actually configured.
//
// So FailOn and FailOnPriority are exclusive. The zero value gates on **P1**, which is the
// product's own ranking rather than the scanner's, and setting FailOn is how a caller says it
// wants the scanner's number instead.
//
// Thresholds are severity bands, the ladder the report prints, rather than SARIF levels. The two
// are not interchangeable: a finding with a CVSS score takes its band from the score, so one a
// scanner emitted as `warning` can be `high`. Gating on the level let such a finding pass a gate
// its reader believed was set to catch it, with the report beside it saying `high`.
//
// FailOnPriority adds component-aware gating: when set (e.g. "P1"), a control also fails if
// any of its findings has a priority band at least that urgent. Because a finding's priority
// already combines its severity with its component's exposure and criticality, this gates
// per component without a separate per-component threshold.
type Policy struct {
	FailOn         sarif.Severity
	PerControl     map[string]sarif.Severity
	FailOnPriority string
	// PerControlBand overrides the band for named controls, and is the band gate's half of
	// PerControl.
	//
	// Two maps rather than one, because a threshold is only meaningful in the vocabulary the gate
	// asks in, and FailOn and FailOnPriority are already a pair for the same reason. A single map
	// would hold values that mean nothing to the gate reading it, which is how a per-control
	// threshold came to be written, reviewed, and dropped without a word.
	PerControlBand map[string]string
}

// GatesOnSeverity reports whether this policy judges a finding's own severity rather than the band
// it landed in.
//
// Set by asking: naming a threshold, globally or for one control, is what chooses the question.
// Nothing named means the default, which is the priority band.
func (p Policy) GatesOnSeverity() bool { return p.FailOn != "" || len(p.PerControl) > 0 }

// bandFor returns the band this control is judged against, or empty where the policy gates on
// severity instead.
//
// An override only applies in the gate's own vocabulary. PerControlBand is filled only on a band
// gate and PerControl only on a severity gate, so neither can quietly answer for the other.
func (p Policy) bandFor(control string) string {
	band := p.PriorityBand()
	if band == "" {
		return ""
	}
	if want, ok := p.PerControlBand[control]; ok && want != "" {
		return want
	}
	return band
}

// DefaultPriority is the band a run fails on when its policy names no threshold of its own.
//
// The product's own ranking rather than the scanner's: severity rates a flaw in the abstract, and
// priority folds in what the descriptor says about the component it was found in, which is the
// thing no scanner can compute. A tool whose default gate is the number a scanner printed is a
// tool whose central claim is off by default.
const DefaultPriority = "P1"

// PriorityBand is the band this policy fails on, or empty where it gates on severity instead.
func (p Policy) PriorityBand() string {
	if p.GatesOnSeverity() {
		return ""
	}
	if p.FailOnPriority != "" {
		return p.FailOnPriority
	}
	return DefaultPriority
}

// thresholdFor returns the effective failure threshold for a control, or empty where this policy
// does not gate on severity at all.
//
// No fallback to a band nobody named. An empty severity has rank 0 and `AtLeast` compares ranks,
// so a threshold left empty and passed through would be at or below every finding there is, and
// the gate would fail on everything rather than on nothing. Evaluate checks for empty first.
func (p Policy) thresholdFor(control string) sarif.Severity {
	if !p.GatesOnSeverity() {
		return ""
	}
	if sev, ok := p.PerControl[control]; ok && sev != "" {
		return sev
	}
	return p.FailOn
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
// randomizes map iteration, so without sorting here the same scan prints its Controls block, and
// writes its report.json, markdown and HTML, in a different order each run. That makes two runs
// of an unchanged repository diff against each other, which is the opposite of what an artifact
// offered as evidence is for, and it contradicts the promise that the same input gives the same
// answer.
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
		// A control fails when it has a finding at or above the severity threshold, or, in the
		// other mode, one at or above the priority band. Never both: the policy is in one mode or
		// the other, and thresholdFor and PriorityBand each answer empty in the mode they do not
		// serve.
		//
		// The threshold is checked for empty before it is compared. An empty band has rank 0 and
		// AtLeast compares ranks, so passing one through would put it at or below every finding
		// there is and fail the gate on everything.
		failedOnSeverity := threshold != "" && highest.AtLeast(threshold) && highest.Rank() > 0
		if failedOnSeverity || p.priorityFails(control, highestPrio) {
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
func (p Policy) priorityFails(control, highestPrio string) bool {
	band := p.bandFor(control)
	if band == "" || highestPrio == "" {
		return false
	}
	return prioritization.Priority(highestPrio).Rank() >= prioritization.Priority(band).Rank()
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
