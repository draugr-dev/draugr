package controllers

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestLicensesInfo(t *testing.T) {
	info := NewLicenses().Info()
	if info.Name != "licenses" || info.Scope != plugin.ScopeComponent {
		t.Errorf("info = %+v", info)
	}
	// A separate control from sca on purpose: it is what lets config.gate.controls hold
	// license policy to a different threshold than vulnerability policy.
	if len(info.DefaultScanners) != 1 || info.DefaultScanners[0] != "trivy-license" {
		t.Errorf("default scanners = %v", info.DefaultScanners)
	}
}

func TestLicensesPlanPerRepository(t *testing.T) {
	comp := &saga.Component{Name: "c", Repositories: []saga.Repository{
		{URL: "https://git/a"}, {URL: "https://git/b", Revision: "v1"},
	}}
	jobs, err := Licenses{}.Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("jobs = %d, want one per repository", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "trivy-license" {
			t.Errorf("scanner = %q", j.Scanner)
		}
		if _, ok := j.Target.(plugin.RepositoryTarget); !ok {
			t.Errorf("target = %T, want a repository", j.Target)
		}
	}
}

func TestLicensesPlanNilComponent(t *testing.T) {
	jobs, err := Licenses{}.Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Errorf("Plan(nil) = %v, %v", jobs, err)
	}
}

func TestLicensePolicyUnionsRatherThanOverrides(t *testing.T) {
	// The one place this control departs from how every other controller merges settings.
	// deepMerge replaces a list outright, so a component adding one denied license would
	// silently discard the organization's — a component quietly opting out of an org license
	// policy, invisible in review. A component can only tighten.
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"deny": []any{"GPL-3.0-only", "AGPL-3.0-only"}},
	}}}
	comp := &saga.Component{Name: "c", Controllers: map[string]saga.ControllerSettings{
		"licenses": {"deny": []any{"Sleepycat"}},
	}}
	cfg := licensePolicy(model, comp)
	deny, _ := cfg["deny"].([]string)
	if strings.Join(deny, ",") != "AGPL-3.0-only,GPL-3.0-only,Sleepycat" {
		t.Errorf("deny = %v, want the org's policy plus the component's, sorted", deny)
	}
}

func TestLicensePolicyDeduplicatesAndSorts(t *testing.T) {
	// Sorted and deduplicated so the job's config — and therefore its cache key — is stable
	// across runs regardless of how the Saga was written.
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"warn": []any{"MPL-2.0", "EPL-2.0"}},
	}}}
	comp := &saga.Component{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"warn": []any{"MPL-2.0"}},
	}}
	warn, _ := licensePolicy(model, comp)["warn"].([]string)
	if strings.Join(warn, ",") != "EPL-2.0,MPL-2.0" {
		t.Errorf("warn = %v, want deduplicated and sorted", warn)
	}
}

func TestLicensePolicyEmptyIsNil(t *testing.T) {
	// No policy means no job config, so the cache key doesn't change for projects that set none.
	if cfg := licensePolicy(saga.Model{}, &saga.Component{}); cfg != nil {
		t.Errorf("licensePolicy = %v, want nil", cfg)
	}
}

func TestLicensePolicyComponentOnly(t *testing.T) {
	comp := &saga.Component{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"deny": []any{"GPL-2.0-only"}},
	}}
	deny, _ := licensePolicy(saga.Model{}, comp)["deny"].([]string)
	if len(deny) != 1 || deny[0] != "GPL-2.0-only" {
		t.Errorf("deny = %v", deny)
	}
}

func TestLicensesAggregate(t *testing.T) {
	reports := []sarif.Report{{Tool: "trivy-license", Results: []sarif.Result{
		{RuleID: "license/AGPL-3.0-only/x", Level: sarif.LevelError},
		{RuleID: "license/GPL-3.0-only/y", Level: sarif.LevelWarning},
		{RuleID: "license/MPL-2.0/z", Level: sarif.LevelNote},
	}}}
	got, err := Licenses{}.Aggregate(reports)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if got.Control != "licenses" {
		t.Errorf("control = %q", got.Control)
	}
	if got.Summary != (plugin.Summary{Errors: 1, Warnings: 1, Notes: 1}) {
		t.Errorf("summary = %+v", got.Summary)
	}
}

func TestLicensesAggregateEmpty(t *testing.T) {
	got, err := Licenses{}.Aggregate(nil)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if got.Summary != (plugin.Summary{}) {
		t.Errorf("summary = %+v, want zero", got.Summary)
	}
}

// A repository somebody else publishes reaches the scanner saying so.
//
// Through the licenses controller because it is the control the case was reported against: a
// denied license in the dependency tree of a repository this team does not publish is not a
// license they chose and not one they can swap out, and a report telling them to change the code
// is telling them to do something impossible.
//
// Two repositories, one declared on the component and one overriding it, because a single
// repository cannot tell a resolved value from a hardcoded one.
func TestALicenseFindingInSomebodyElsesRepositoryIsMarkedUpstream(t *testing.T) {
	comp := &saga.Component{
		Name:    "analytics-console",
		BuiltBy: saga.BuiltByUpstream,
		Repositories: []saga.Repository{
			{URL: "https://github.com/vendor/console.git"},
			{URL: "https://github.com/acme/console-config.git", BuiltBy: saga.BuiltBySelf},
		},
	}
	model := saga.Model{Config: saga.Config{
		Controllers: map[string]saga.ControllerSettings{"licenses": {"enabled": true}},
	}}

	jobs, err := Licenses{}.Plan(model, comp)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("planned %d jobs, want one per repository", len(jobs))
	}

	want := map[string]bool{
		"https://github.com/vendor/console.git":      true,
		"https://github.com/acme/console-config.git": false,
	}
	for _, job := range jobs {
		target, ok := job.Target.(plugin.RepositoryTarget)
		if !ok {
			t.Fatalf("target is %T, want a repository", job.Target)
		}
		if target.Upstream != want[target.URL] {
			t.Errorf("%s: upstream = %v, want %v — the component declares upstream and the "+
				"second repository overrides it", target.URL, target.Upstream, want[target.URL])
		}
	}
}
