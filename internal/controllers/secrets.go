package controllers

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const gitleaksScanner = "gitleaks"

// Secrets is the secret-detection control: it scans a component's repositories for leaked
// credentials. Any detected secret is reported at the level `error`, and held at the minimum
// severity and the context tier floors.go declares for it, so a leaked secret fails the gate
// regardless of how the scanner rated it.
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
	// so an option written there would neither take effect nor be reported, and the scanner's
	// declared schema, which exists to make that an error, would never be consulted.
	selections := resolveScanners(model, comp, "secrets", []string{gitleaksScanner})
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories)*len(selections))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision,
			Paths: repo.Paths, Ignore: repo.Ignore,
			Upstream: comp.PublishedBy(repo) == saga.BuiltByUpstream}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
	}
	return jobs, nil
}

// Aggregate merges the scan reports and sets every finding's level to error.
//
// The level is the wire value. GitHub code scanning reads it as the alert's severity, and its
// default check fails on an alert at `error` that carries no security-severity, which a secret
// does not; JUnit writes it as the failure type; and the per-control error count tallies it. A
// detected secret is an error on every one of those, whatever the scanner wrote. Gitleaks writes
// no level, so SARIF's default, `warning`, would otherwise reach all of them.
//
// The severity is not the wire value, and the scanner's answer stays readable. Where the scanner's
// level decided the finding's severity, it is recorded as the finding's rating before the level is
// replaced, so the severity a report carries is the scanner's and a raise to the control's minimum
// severity is recorded as one. A score or a rating the scanner gave is already what decides the
// severity, and is left as it is.
func (Secrets) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	for i := range merged.Results {
		res := &merged.Results[i]
		said, level := res.Severity(""), res.Level
		res.Level = sarif.LevelError
		if res.Severity("") != said {
			res.Rating = levelRating(said, level)
		}
	}
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "secrets",
		Report:  merged,
		Summary: plugin.Summary{Errors: counts.Error, Warnings: counts.Warning, Notes: counts.Note},
	}, nil
}

// levelRating is the rating a scanner's SARIF level gave a finding, kept where the level itself is
// about to be replaced. No detail, because the report prints a rating's detail under the row and a
// level is not a finer rating than the severity printed beside it; the level stays in the fields.
func levelRating(severity sarif.Severity, level sarif.Level) *sarif.Rating {
	r := &sarif.Rating{Severity: severity}
	if level != "" {
		r.Fields = map[string]string{"level": string(level)}
	}
	return r
}
