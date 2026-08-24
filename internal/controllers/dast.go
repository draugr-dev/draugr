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
		Summary:         "Find problems only visible from outside a running app (dynamic testing).",
		DefaultScanners: []string{nucleiScanner},
	}
}

// Plan produces one scan job per host with a URL declared on the component.
func (DAST) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	// Through resolveScanners rather than named directly, even with one scanner to choose from.
	// Naming it here would discard the descriptor's dast block before anything could look at it,
	// so an option written there would neither take effect nor be reported — and the scanner's
	// declared schema, which exists to make that an error, would never be consulted.
	selections := resolveScanners(model, comp, "dast", []string{nucleiScanner})
	jobs := make([]plugin.ScanJob, 0, len(comp.Hosts)*len(selections))
	for _, host := range comp.Hosts {
		if host.URL == "" {
			continue
		}
		target := plugin.HostTarget{
			Name: host.Name, URL: host.URL, Type: host.Type,
			Auth: hostAuth(host.Auth), Spec: hostSpec(host.Spec),
			Environment: host.Environment,
		}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
	}
	return jobs, nil
}

// hostAuth converts a descriptor's auth block into what a scanner is given.
//
// Only dast reads it today. The passive host controls — headers, tls — probe the endpoint too and
// would see a different application behind a login, but authenticating on their behalf is a
// separate decision from authenticating a scan whose purpose is to send traffic.
func hostAuth(a *saga.HostAuth) *plugin.HostAuth {
	if a == nil {
		return nil
	}
	return &plugin.HostAuth{Kind: a.Type, Header: a.Header, TokenEnv: a.TokenEnv}
}

// hostSpec converts a descriptor's spec block into what a scanner is given.
func hostSpec(s *saga.HostSpec) *plugin.HostSpec {
	if s == nil {
		return nil
	}
	return &plugin.HostSpec{Path: s.Path, Methods: s.Methods}
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
