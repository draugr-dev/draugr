package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const nucleiScanner = "nuclei"

// DAST is the dynamic application security testing control. It plans one Nuclei scan per running
// host declared on a component and aggregates the findings. Complements the "headers" control:
// dast covers runtime issues (exposures, misconfigurations, info disclosure, outdated libraries)
// while headers owns HTTP security-header checks.
type DAST struct{}

// NewDAST returns the dast controller.
func NewDAST() plugin.Controller { return DAST{} }

// Info identifies the controller (component-scoped).
func (DAST) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            "dast",
		Scope:           plugin.ScopeComponent,
		Summary:         "Probe a component's running endpoints for runtime vulnerabilities.",
		DefaultScanners: []string{nucleiScanner},
	}
}

// Plan produces one scan job per host with a URL declared on the component.
func (DAST) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	jobs := make([]plugin.ScanJob, 0, len(comp.Hosts))
	for _, host := range comp.Hosts {
		if host.URL == "" {
			continue
		}
		target := plugin.HostTarget{Name: host.Name, URL: host.URL, Type: host.Type}
		jobs = append(jobs, plugin.ScanJob{
			Scanner: nucleiScanner,
			Target:  target,
		})
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (DAST) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "dast",
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
