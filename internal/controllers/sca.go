package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const trivyFSScanner = "trivy-fs"

// govulncheckScanner decides reachability; it is enabled by config.reachability, never by a
// scanner block. See ReachabilityConfig.
const govulncheckScanner = "govulncheck"

// SCA is the Software Composition Analysis control: dependency vulnerabilities (and, later,
// licenses) for a component's source repositories. It plans one scan per repository.
type SCA struct{}

// NewSCA returns the sca controller.
func NewSCA() plugin.Controller { return SCA{} }

// Info identifies the controller (component-scoped).
func (SCA) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            "sca",
		Scope:           plugin.ScopeComponent,
		Summary:         "Scan a repo's dependencies for known vulnerabilities (Software Composition Analysis).",
		DefaultScanners: []string{"trivy-fs"},
	}
}

// Plan produces one scan job per repository, for each scanner this component selects.
//
// Trivy runs by default; anything else is opt-in, because the others reach a third party and one
// of them writes into an account. See scanner selection in the Saga reference.
func (SCA) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	selections := resolveScanners(model, comp, "sca", []string{trivyFSScanner})
	// Reachability analyzers are planned from config.reachability rather than selected from the
	// scanner block, because enabling one is a decision about how findings are ranked rather than
	// about which tools run. They still plan as sca jobs: an analyzer needs the same checkout the
	// manifest scanner reads.
	for _, name := range reachabilitySelections(model) {
		selections = append(selections, scannerSelection{Name: name})
	}
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories)*len(selections))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision, Paths: repo.Paths, Ignore: repo.Ignore}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
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
