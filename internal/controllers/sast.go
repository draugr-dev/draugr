package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const semgrepScanner = "semgrep"

// SAST is the Static Application Security Testing control: it analyzes a component's own
// source code (not its dependencies) for security bugs. It plans one scan per repository.
type SAST struct{}

// NewSAST returns the sast controller.
func NewSAST() plugin.Controller { return SAST{} }

// Info identifies the controller (component-scoped).
func (SAST) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sast", Scope: plugin.ScopeComponent}
}

// Plan produces one scan job per repository declared on the component.
func (SAST) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision, Paths: repo.Paths}
		jobs = append(jobs, plugin.ScanJob{
			Scanner:  semgrepScanner,
			Target:   target,
			CacheKey: plugin.ComputeCacheKey(semgrepScanner, "", target, nil),
		})
	}
	return jobs, nil
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
