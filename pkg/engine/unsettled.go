package engine

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// setUnsettledApart moves each check a scanner left for a person out of its control's findings and
// into the control's list of unsettled checks, and says how many suppressed findings that took out
// of the count of suppressed ones.
//
// A check the benchmark leaves to a person is not a finding. Nothing was seen to fail, and nothing
// changed in the cluster clears it, so as a finding it took a band like a real failure, counted
// toward the gate and repeated on every run after somebody had reviewed it. Listed apart, the
// person who does the review still has every one of them, by rule id, in the report and in SARIF.
//
// After correlation, so a check two scanners report is listed once: under the copy correlation
// counted, which is the undecided copy only where no scanner decided the check. A referral of a
// check another scanner decided is dropped rather than listed, because that scanner's verdict is
// in the run's decided list and nothing is left for a person.
//
// A check config.exclude names keeps the exclusion's reason, which is how a review is recorded,
// and leaves the count of suppressed findings, since it was never a finding.
func setUnsettledApart(controls map[string]plugin.ControlResult) (leftSuppressed int) {
	for name, cr := range controls {
		decided := map[string]bool{}
		for _, t := range cr.Report.Decided {
			decided[t.Key()] = true
		}
		var kept []sarif.Result
		var unsettled []sarif.UnsettledCheck
		for _, r := range cr.Report.Results {
			if !r.Undecided {
				kept = append(kept, r)
				continue
			}
			if r.Suppressed() {
				leftSuppressed++
			}
			if r.Correlated() {
				continue
			}
			rule := cr.Report.Rules[r.RuleID]
			if check, ok := benchmarkCheckOf(rule); ok && decided[check] {
				continue
			}
			title := rule.ShortDescription
			if title == "" {
				title = r.Message
			}
			unsettled = append(unsettled, sarif.UnsettledCheck{
				Scanner: r.Tool, RuleID: r.RuleID, Title: title,
				Component: r.Component, Location: r.Location.URI,
				Kind: sarif.UnsettledManual, Suppression: r.Suppression,
			})
		}
		if len(unsettled) == 0 && len(kept) == len(cr.Report.Results) {
			continue
		}
		cr.Report.Results = kept
		cr.Report.UnsettledChecks = append(cr.Report.UnsettledChecks, unsettled...)
		counts := cr.Report.Counts()
		cr.Summary = plugin.Summary{Errors: counts.Error, Warnings: counts.Warning, Notes: counts.Note}
		controls[name] = cr
	}
	return leftSuppressed
}
