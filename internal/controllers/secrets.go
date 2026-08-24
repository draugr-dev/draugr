package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const gitleaksScanner = "gitleaks"

// Secrets is the secret-detection control: it scans a component's repositories for leaked
// credentials. Any detected secret is treated as an error — a leaked secret should fail
// the gate regardless of how the scanner rated it.
type Secrets struct{}

// NewSecrets returns the secrets controller.
func NewSecrets() plugin.Controller { return Secrets{} }

// Info identifies the controller (component-scoped).
func (Secrets) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            "secrets",
		Scope:           plugin.ScopeComponent,
		Summary:         "Find passwords and keys committed by accident, history included.",
		DefaultScanners: []string{"gitleaks"},
	}
}

// Plan produces one scan job per repository declared on the component.
func (Secrets) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	// Through resolveScanners rather than named directly, even with one scanner to choose from.
	// Naming it here would discard the descriptor's secrets block before anything could look at it,
	// so an option written there would neither take effect nor be reported — and the scanner's
	// declared schema, which exists to make that an error, would never be consulted.
	selections := resolveScanners(model, comp, "secrets", []string{gitleaksScanner})
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories)*len(selections))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision, Paths: repo.Paths, Ignore: repo.Ignore}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
	}
	return jobs, nil
}

// Aggregate merges the scan reports and escalates every finding to error severity — a
// detected secret is always gate-failing.
func (Secrets) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	for i := range merged.Results {
		merged.Results[i].Level = sarif.LevelError
	}
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "secrets",
		Report:  merged,
		Summary: plugin.Summary{Errors: counts.Error, Warnings: counts.Warning, Notes: counts.Note},
	}, nil
}
