package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const draugrHeadersScanner = "draugr-headers"

// Headers is the HTTP security-header control. It plans one native header scan per host
// declared on a component and aggregates the findings. No external tool is required.
type Headers struct{}

// NewHeaders returns the headers controller.
func NewHeaders() plugin.Controller { return Headers{} }

// Info identifies the controller (component-scoped).
func (Headers) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            "headers",
		Scope:           plugin.ScopeComponent,
		Summary:         "Check HTTP security headers on a component's running endpoints.",
		DefaultScanners: []string{"draugr-headers"},
	}
}

// Plan produces one scan job per host with a URL declared on the component.
func (Headers) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	// Through resolveScanners rather than named directly, even with one scanner to choose from.
	// Naming it here would discard the descriptor's headers block before anything could look at it,
	// so an option written there would neither take effect nor be reported — and the scanner's
	// declared schema, which exists to make that an error, would never be consulted.
	selections := resolveScanners(model, comp, "headers", []string{draugrHeadersScanner})
	jobs := make([]plugin.ScanJob, 0, len(comp.Hosts)*len(selections))
	for _, host := range comp.Hosts {
		if host.URL == "" {
			continue
		}
		target := plugin.HostTarget{
			Name: host.Name, URL: host.URL, Type: host.Type,
			Environment: host.Environment,
		}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
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
