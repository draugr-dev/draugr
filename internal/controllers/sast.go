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

// Plan produces a scan job for each repository × each selected sast scanner. The scanner set
// is controllers.sast.scanners (default [semgrep]); e.g. a Go component can opt into gosec
// alongside Semgrep with `scanners: [semgrep, gosec]`.
func (SAST) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	scanners := sastScanners(model, comp)
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories)*len(scanners))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision, Paths: repo.Paths}
		for _, scanner := range scanners {
			jobs = append(jobs, plugin.ScanJob{Scanner: scanner, Target: target})
		}
	}
	return jobs, nil
}

// SASTScannerSet returns the set of sast scanner names the model will actually run — the union
// of the selection across all components (each resolved against its override / the project
// default). Used to decide which sast tools are truly required (e.g. gosec only when selected),
// rather than every scanner that *could* serve the control.
func SASTScannerSet(model saga.Model) map[string]bool {
	set := make(map[string]bool)
	for i := range model.Components {
		for _, s := range sastScanners(model, &model.Components[i]) {
			set[s] = true
		}
	}
	return set
}

// sastScanners resolves the scanners to run for a component: the component's
// controllers.sast.scanners override, else the project-level setting, else [semgrep].
func sastScanners(model saga.Model, comp *saga.Component) []string {
	if s := scannersSetting(comp.Controllers); s != nil {
		return s
	}
	if s := scannersSetting(model.Config.Controllers); s != nil {
		return s
	}
	return []string{semgrepScanner}
}

// scannersSetting reads a controller map's sast.scanners list, or nil when unset/empty.
func scannersSetting(controllers map[string]saga.ControllerSettings) []string {
	settings, ok := controllers["sast"]
	if !ok {
		return nil
	}
	raw, ok := settings["scanners"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if name, ok := v.(string); ok && name != "" {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
