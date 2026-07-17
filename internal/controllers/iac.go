package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const trivyConfigScanner = "trivy-config"

// IAC is the Infrastructure-as-Code / misconfiguration control: it scans a component's
// repositories for insecure IaC (Terraform, Kubernetes manifests, Dockerfiles, …). It plans
// one scan per repository.
type IAC struct{}

// NewIAC returns the iac controller.
func NewIAC() plugin.Controller { return IAC{} }

// Info identifies the controller (component-scoped).
func (IAC) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            "iac",
		Scope:           plugin.ScopeComponent,
		Summary:         "Scan Infrastructure-as-Code for insecure misconfigurations.",
		DefaultScanners: []string{"trivy-config"},
	}
}

// Plan produces one scan job per repository declared on the component.
func (IAC) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision, Paths: repo.Paths}
		jobs = append(jobs, plugin.ScanJob{
			Scanner: trivyConfigScanner,
			Target:  target,
		})
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity. Trivy reports
// per-check severity, so severity is taken as reported.
func (IAC) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "iac",
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
