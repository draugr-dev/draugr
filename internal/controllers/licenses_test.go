package controllers

import (
	"slices"
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
		"licenses": {"deny": []any{map[string]any{"id": "GPL-3.0-only"}, map[string]any{"id": "AGPL-3.0-only"}}},
	}}}
	comp := &saga.Component{Name: "c", Controllers: map[string]saga.ControllerSettings{
		"licenses": {"deny": []any{map[string]any{"id": "Sleepycat"}}},
	}}
	cfg := licensePolicy(model, comp)
	deny := ids(cfg["deny"])
	if strings.Join(deny, ",") != "AGPL-3.0-only,GPL-3.0-only,Sleepycat" {
		t.Errorf("deny = %v, want the org's policy plus the component's, sorted", deny)
	}
}

func TestLicensePolicyDeduplicatesAndSorts(t *testing.T) {
	// Sorted and deduplicated so the job's config — and therefore its cache key — is stable
	// across runs regardless of how the Saga was written.
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"warn": []any{map[string]any{"id": "MPL-2.0"}, map[string]any{"id": "EPL-2.0"}}},
	}}}
	comp := &saga.Component{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"warn": []any{map[string]any{"id": "MPL-2.0"}}},
	}}
	warn := ids(licensePolicy(model, comp)["warn"])
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
		"licenses": {"deny": []any{map[string]any{"id": "GPL-2.0-only"}}},
	}}
	deny := ids(licensePolicy(saga.Model{}, comp)["deny"])
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

// A policy entry written with its reason names the same license, and one written short still
// does. Two components, because a rule that collapses per-component policy into one is invisible
// with a single component and picks a winner with two.
func TestLicensePolicyReadsBothEntryForms(t *testing.T) {
	model := saga.Model{
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			licensesControl: {denyKey: []any{
				map[string]any{"id": "AGPL-3.0-only", "reason": "we ship binaries to customers"},
			}},
		}},
	}
	api := &saga.Component{
		Name:         "api",
		Repositories: []saga.Repository{{URL: "https://example.test/api.git"}},
		Controllers: map[string]saga.ControllerSettings{
			licensesControl: {denyKey: []any{map[string]any{"id": "SSPL-1.0"}}},
		},
	}
	web := &saga.Component{
		Name:         "web",
		Repositories: []saga.Repository{{URL: "https://example.test/web.git"}},
		Controllers: map[string]saga.ControllerSettings{
			licensesControl: {warnKey: []any{
				map[string]any{"id": "MPL-2.0", "reason": "file-level copyleft, worth a look"},
			}},
		},
	}

	// The project's denial reaches both, and neither component's own list replaces it.
	for _, tc := range []struct {
		comp *saga.Component
		deny []string
		warn []string
	}{
		{api, []string{"AGPL-3.0-only", "SSPL-1.0"}, nil},
		{web, []string{"AGPL-3.0-only"}, []string{"MPL-2.0"}},
	} {
		got := licensePolicy(model, tc.comp)
		if deny := ids(got[denyKey]); !slices.Equal(deny, tc.deny) {
			t.Errorf("%s: deny = %v, want %v", tc.comp.Name, deny, tc.deny)
		}
		if tc.warn == nil {
			if _, ok := got[warnKey]; ok {
				t.Errorf("%s: warn = %v, want none", tc.comp.Name, got[warnKey])
			}
			continue
		}
		if warn := ids(got[warnKey]); !slices.Equal(warn, tc.warn) {
			t.Errorf("%s: warn = %v, want %v", tc.comp.Name, warn, tc.warn)
		}
	}
}

// ids reads the identifiers out of a resolved policy list, which is entries rather than strings
// so that one shape reaches the scanner and the schema describes exactly that.
func ids(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if id, ok := plugin.EntryID(item); ok {
			out = append(out, id)
		}
	}
	return out
}
