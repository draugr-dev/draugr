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
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision, Paths: repo.Paths}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
	}
	return jobs, nil
}

// SASTScannerSet returns the set of sast scanner names the model will actually run — the union
// of the selection across all components. Used to decide which sast tools are truly required
// (e.g. gosec only when enabled), rather than every scanner that *could* serve the control.
func SASTScannerSet(model saga.Model) map[string]bool {
	set := make(map[string]bool)
	for i := range model.Components {
		for _, sel := range resolveScanners(model, &model.Components[i], "sast", []string{semgrepScanner}) {
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
