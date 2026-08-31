package controllers

import (
	"slices"
	"sort"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	trivyLicenseScanner = "trivy-license"
	licensesControl     = "licenses"
	// denyKey and warnKey name SPDX ids the project will not accept, or wants flagged. They
	// override whatever category Trivy assigned.
	denyKey = "deny"
	warnKey = "warn"
)

// Licenses reports dependency licenses that carry an obligation.
//
// A separate control rather than part of `sca`, deliberately. License risk is not a
// vulnerability: the exposure is legal and commercial, the policy is owned by different people,
// and it changes on a different cadence. Keeping it separate is also what lets
// `config.gate.controls` hold it to its own threshold — "fail on a forbidden license but only
// warn on a medium CVE" is a reasonable position that one shared threshold cannot express.
type Licenses struct{}

// NewLicenses returns the licenses controller.
func NewLicenses() plugin.Controller { return Licenses{} }

// Info identifies the controller (component-scoped).
func (Licenses) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            licensesControl,
		Scope:           plugin.ScopeComponent,
		Summary:         "Report license terms attached to code you did not write, where they carry an obligation.",
		DefaultScanners: []string{trivyLicenseScanner},
	}
}

// Plan produces one scan job per repository and per image, carrying the resolved license policy.
//
// Both, because the question the control answers — what am I obliged by — has no target kind in
// it. A license obligation inside an image was invisible while this planned repositories only, and
// silently so: the control ran, reported covered, and the surface it had not examined had no name
// in the output.
//
// The same policy reaches both. Which licenses a release may carry is a decision about the
// release, not about where the code happens to sit, so a component whose deny list differs by
// target kind is not a thing this control lets anybody express.
func (Licenses) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	policy := licensePolicy(model, comp)
	selections := resolveScanners(model, comp, "licenses", []string{trivyLicenseScanner})
	// Repositories first, so a component declaring both reports its own tree before what it runs.
	targets := make([]plugin.Target, 0, len(comp.Repositories)+len(comp.Images))
	for _, repo := range comp.Repositories {
		targets = append(targets, plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision,
			Paths: repo.Paths, Ignore: repo.Ignore,
			Upstream: comp.PublishedBy(repo) == saga.BuiltByUpstream})
	}
	for _, img := range comp.Images {
		targets = append(targets, plugin.ImageTarget{Ref: img.Image, Digest: img.Digest,
			Upstream: comp.PublishesImage(img) == saga.BuiltByUpstream})
	}

	jobs := make([]plugin.ScanJob, 0, len(targets)*len(selections))
	for _, target := range targets {
		for _, sel := range selections {
			// The policy is the control's, so every scanner serving it judges by the same lists;
			// a scanner's own block adds to that rather than replacing it.
			cfg := plugin.Config{}
			for k, v := range sel.Config {
				cfg[k] = v
			}
			for k, v := range policy {
				cfg[k] = v
			}
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: cfg})
		}
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (Licenses) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: licensesControl,
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}

// licensePolicy resolves deny/warn for a component: the **union** of the project's lists and the
// component's.
//
// Union, not override, and this is the one place the licenses control deliberately departs from
// how every other controller merges settings. The general rule is deep-merge with the component
// winning — which replaces a list outright. Applied here, a component that added one denied
// license would silently discard the organization's:
//
//	config.controllers.licenses.deny:  [GPL-3.0-only, AGPL-3.0-only]   # the org's policy
//	components[0].controllers.licenses.deny: [Sleepycat]               # would drop both
//
// A component quietly opting out of an organization's license policy is precisely the failure a
// license gate exists to prevent, and it would be invisible in review. So a component can only
// **tighten**. Loosening has exactly one route — `config.exclude`, which requires a reason and
// leaves the finding in the report, suppressed and auditable, rather than deleted.
func licensePolicy(model saga.Model, comp *saga.Component) plugin.Config {
	deny := unionSetting(model.Config.Controllers, comp, denyKey)
	warn := unionSetting(model.Config.Controllers, comp, warnKey)
	if len(deny) == 0 && len(warn) == 0 {
		return nil
	}
	cfg := plugin.Config{}
	if len(deny) > 0 {
		cfg[denyKey] = deny
	}
	if len(warn) > 0 {
		cfg[warnKey] = warn
	}
	return cfg
}

// unionSetting collects a string list from the project and component blocks for the licenses
// control, deduplicated and sorted so a scan is reproducible and its cache key is stable.
func unionSetting(project map[string]saga.ControllerSettings, comp *saga.Component, key string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(settings saga.ControllerSettings) {
		for _, v := range settingStrings(settings, key) {
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	add(project[licensesControl])
	if comp != nil {
		add(comp.Controllers[licensesControl])
	}
	sort.Strings(out)
	return out
}

// settingStrings reads a list of strings from a controller settings block, tolerating the []any
// that YAML decoding produces.
func settingStrings(settings saga.ControllerSettings, key string) []string {
	if settings == nil {
		return nil
	}
	switch v := settings[key].(type) {
	case []string:
		return slices.Clone(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
