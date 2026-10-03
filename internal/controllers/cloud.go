package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	cloudControl   = "cloud"
	prowlerScanner = "prowler"
)

// Cloud checks the cloud accounts a component runs in against the provider's CIS benchmark, by
// reading the live account rather than the infrastructure code that describes it.
//
// Component-scoped like kubernetes, for the same reason: `cloud:` is a list on a component, and
// two components in one account produce two jobs the engine collapses into one scan when they
// claim the same regions.
type Cloud struct{}

// NewCloud returns the cloud controller.
func NewCloud() plugin.Controller { return Cloud{} }

// Info identifies the controller.
func (Cloud) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            cloudControl,
		Scope:           plugin.ScopeComponent,
		Summary:         "Check a live cloud account against the provider's CIS Benchmark.",
		DefaultScanners: []string{prowlerScanner},
	}
}

// Plan produces one job per account entry on the component, for each scanner selected.
func (Cloud) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	selections := resolveScanners(model, comp, cloudControl, []string{prowlerScanner})
	var jobs []plugin.ScanJob
	for _, ref := range comp.Cloud {
		// Validation refuses a name with no declaration, so a missing one here is a model built in
		// code, and the scanner refuses the empty provider it carries.
		account := model.Accounts[ref.Account]
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{
				Scanner: sel.Name,
				Target: plugin.AccountTarget{
					Account: ref.Account, Provider: string(account.Provider), ID: account.ID(),
					Regions: ref.Regions,
				},
				Config: sel.Config,
			})
		}
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (Cloud) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: cloudControl,
		Report:  merged,
		Summary: plugin.Summary{Errors: counts.Error, Warnings: counts.Warning, Notes: counts.Note},
	}, nil
}
