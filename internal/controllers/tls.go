package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const draugrTLSScanner = "draugr-tls"

// TLS is the transport-security control. It plans one native TLS probe per host declared on a
// component and aggregates the findings. No external tool is required.
type TLS struct{}

// NewTLS returns the tls controller.
func NewTLS() plugin.Controller { return TLS{} }

// Info identifies the controller (component-scoped).
func (TLS) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            "tls",
		Scope:           plugin.ScopeComponent,
		Summary:         "Check the certificates and encryption a component's running endpoints offer visitors.",
		DefaultScanners: []string{draugrTLSScanner},
	}
}

// Plan produces one scan job per host with a URL declared on the component, honoring the
// Saga's per-scanner selection and config under controllers.tls.<scanner>.
func (TLS) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	selections := resolveScanners(model, comp, "tls", []string{draugrTLSScanner})
	jobs := make([]plugin.ScanJob, 0, len(comp.Hosts)*len(selections))
	for _, host := range comp.Hosts {
		if host.URL == "" {
			continue
		}
		target := plugin.HostTarget{
			Name: host.Name, URL: host.URL, Type: host.Type,
		}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{
				Scanner: sel.Name,
				Target:  target,
				Config:  sel.Config,
			})
		}
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (TLS) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "tls",
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
