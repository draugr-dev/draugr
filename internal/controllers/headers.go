package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const httpHeadersScanner = "http-headers"

// Headers is the HTTP security-header control. It plans one native header scan per host
// declared on a component and aggregates the findings. No external tool is required.
type Headers struct{}

// NewHeaders returns the headers controller.
func NewHeaders() plugin.Controller { return Headers{} }

// Info identifies the controller (component-scoped).
func (Headers) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "headers", Scope: plugin.ScopeComponent}
}

// Plan produces one scan job per host with a URL declared on the component.
func (Headers) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
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
			Scanner: httpHeadersScanner,
			Target:  target,
		})
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (Headers) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "headers",
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
