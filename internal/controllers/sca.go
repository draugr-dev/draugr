package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const trivyFSScanner = "trivy-fs"

// SCA is the Software Composition Analysis control: dependency vulnerabilities (and, later,
// licenses) for a component's source repositories. It plans one scan per repository.
type SCA struct{}

// NewSCA returns the sca controller.
func NewSCA() plugin.Controller { return SCA{} }

// Info identifies the controller (component-scoped).
func (SCA) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sca", Scope: plugin.ScopeComponent}
}

// Plan produces one scan job per repository declared on the component.
func (SCA) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision, Paths: repo.Paths}
		jobs = append(jobs, plugin.ScanJob{
			Scanner:  trivyFSScanner,
			Target:   target,
			CacheKey: plugin.ComputeCacheKey(trivyFSScanner, "", target, nil),
		})
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (SCA) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "sca",
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
