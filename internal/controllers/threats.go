package controllers

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const urlhausScannerName = "urlhaus"

// Threats is the threat-intelligence control. It asks whether a component's own hosts are
// already known to the outside world as hostile.
//
// The other host controls examine something you run: its headers, its TLS, its responses to a
// probe. This one examines what other people have already observed about it, which is the only
// way to learn that your host is serving malware from a path you do not know exists — a scanner
// pointed at your own endpoint would never find it.
//
// Off by default, like every control, and for a sharper reason than most: running it tells a
// third party that your hosts exist.
type Threats struct{}

// NewThreats returns the threats controller.
func NewThreats() plugin.Controller { return Threats{} }

// Info identifies the controller (component-scoped).
func (Threats) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            "threats",
		Scope:           plugin.ScopeComponent,
		Summary:         "Check whether a component's hosts are known to threat-intelligence feeds.",
		DefaultScanners: []string{urlhausScannerName},
	}
}

// Plan produces one lookup per host with a URL declared on the component.
//
// De-duplicated by hostname: two endpoints on one host are one question to abuse.ch, and asking
// twice would spend a rate limit to receive the same answer.
func (Threats) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	seen := map[string]bool{}
	jobs := make([]plugin.ScanJob, 0, len(comp.Hosts))
	for _, host := range comp.Hosts {
		if host.URL == "" {
			continue
		}
		name, err := hostnameFor(host.URL)
		if err != nil || seen[name] {
			// A URL that cannot be parsed is left to the scanner, which reports it properly
			// rather than being silently dropped at planning time.
			if err == nil {
				continue
			}
			name = host.URL
		}
		seen[name] = true
		jobs = append(jobs, plugin.ScanJob{
			Scanner: urlhausScannerName,
			Target:  plugin.HostTarget{Name: host.Name, URL: host.URL, Type: host.Type},
		})
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (Threats) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "threats",
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}

// hostnameFor reads the hostname out of a declared URL, for de-duplication only.
func hostnameFor(raw string) (string, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("no host in %q", raw)
	}
	return u.Hostname(), nil
}
