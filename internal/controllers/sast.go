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
		Summary:         "Static analysis of a repo's own source code for security bugs.",
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
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision, Paths: repo.Paths, Ignore: repo.Ignore}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
	}
	return jobs, nil
}

// SelectedScanners returns the scanner names a control will actually run for this model — the
// union of the selection across every component.
//
// This is what a control *requires*, as opposed to every scanner that could serve it. Those
// differ wherever a control has more than one scanner: `sast` demanding gosec from a project that
// never enabled it, or `infrastructure` demanding kube-bench and kubectl when the default reads
// the API and needs neither. Either way the report is a list of tools to go and install that the
// scan would not have used — and, worse, a missing one reads as a control that cannot run.
//
// defaults must be the controller's own DefaultScanners, so the answer matches what Plan will do.
func SelectedScanners(model saga.Model, control string, defaults []string) map[string]bool {
	set := make(map[string]bool)
	if len(model.Components) == 0 {
		for _, sel := range resolveScanners(model, nil, control, defaults) {
			set[sel.Name] = true
		}
		return set
	}
	for i := range model.Components {
		for _, sel := range resolveScanners(model, &model.Components[i], control, defaults) {
			set[sel.Name] = true
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
