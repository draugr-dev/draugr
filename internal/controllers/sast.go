package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const semgrepScanner = "semgrep"

// SAST is the Static Application Security Testing control: it analyzes a component's own
// source code (not its dependencies) for security bugs. It plans one scan per repository, per
// selected scanner.
type SAST struct{}

// NewSAST returns the sast controller.
func NewSAST() plugin.Controller { return SAST{} }

// Info identifies the controller (component-scoped).
func (SAST) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            "sast",
		Scope:           plugin.ScopeComponent,
		Summary:         "Find patterns in a repo's own code that let somebody in (static analysis).",
		DefaultScanners: []string{"semgrep"},
	}
}

// Plan produces a scan job for each repository × each selected sast scanner. Semgrep runs by
// default; a component opts a non-default scanner in per scanner block, e.g. a Go component
// enables gosec with `controllers.sast.gosec.enabled: true`.
func (SAST) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	selections := resolveScanners(model, comp, "sast", []string{semgrepScanner})
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories)*len(selections))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision,
			Paths: repo.Paths, Ignore: repo.Ignore,
			Upstream: comp.PublishedBy(repo) == saga.BuiltByUpstream}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
	}
	return jobs, nil
}

// SelectedScanners returns the scanner names a control will actually run for this model, the
// union of the selection across every component.
//
// This is what a control *requires*, as opposed to every scanner that could serve it. Those
// differ wherever a control has more than one scanner: `sast` demanding gosec from a project that
// never enabled it, or `infrastructure` demanding kube-bench and kubectl when the default reads
// the API and needs neither. Either way the report is a list of tools to go and install that the
// scan would not have used, and, worse, a missing one reads as a control that cannot run.
//
// Answered by Plan itself, so it cannot drift from what a scan does. It was worked out beside
// Plan from the descriptor's scanner blocks, which is right for every control that chooses from
// them and wrong for one that chooses on something else.
func SelectedScanners(model saga.Model, c plugin.Controller) map[string]bool {
	info := c.Info()
	set := make(map[string]bool)

	// What the control would plan, which is the answer rather than a derivation of it. `provenance`
	// picks its verifier per image from the matched signer's trust model, so a descriptor with no
	// `x509:` signer never runs notation however its scanner blocks read, and nothing outside the
	// control can see that. Plan is pure here: every one of them expands a model into job structs
	// and touches no file, socket or subprocess.
	planned := func(comp *saga.Component) bool {
		jobs, err := c.Plan(model, comp)
		if err != nil {
			// A descriptor this control refuses. `doctor` validates before it gets here, so this is
			// the narrow case of a control refusing what the schema allowed, and the reader is
			// better served by the wider list than by nothing.
			return false
		}
		for _, j := range jobs {
			set[j.Scanner] = true
		}
		return true
	}
	fallback := func(comp *saga.Component) {
		for _, sel := range resolveScanners(model, comp, info.Name, info.DefaultScanners) {
			set[sel.Name] = true
		}
	}

	if len(model.Components) == 0 {
		if !planned(nil) {
			fallback(nil)
		}
		return set
	}
	for i := range model.Components {
		if !planned(&model.Components[i]) {
			fallback(&model.Components[i])
		}
	}
	return set
}

// Aggregate merges the scan reports and summarizes findings by severity. Semgrep emits
// per-rule SARIF levels, so severity is taken as reported.
func (SAST) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "sast",
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
