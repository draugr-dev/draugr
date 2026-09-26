package controllers

import (
	"reflect"
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
	// The one place this control departs from how every other controller merges settings. deepMerge
	// replaces a list outright, so a component adding one denied license would silently discard the
	// organization's, a component quietly opting out of an org license policy, invisible in review. A
	// component can only tighten.
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"licenses": {"deny": []any{"GPL-3.0-only", "AGPL-3.0-only"}},
	}}}
	comp := &saga.Component{Name: "c", Controls: map[string]saga.ControllerSettings{
		"licenses": {"deny": []any{"Sleepycat"}},
	}}
	cfg := licensePolicy(model, comp)
	deny, _ := cfg["deny"].([]string)
	if strings.Join(deny, ",") != "AGPL-3.0-only,GPL-3.0-only,Sleepycat" {
		t.Errorf("deny = %v, want the org's policy plus the component's, sorted", deny)
	}
}

func TestLicensePolicyDeduplicatesAndSorts(t *testing.T) {
	// Sorted and deduplicated so the job's config, and therefore its cache key. Is stable across runs
	// regardless of how the Saga was written.
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"licenses": {"warn": []any{"MPL-2.0", "EPL-2.0"}},
	}}}
	comp := &saga.Component{Controls: map[string]saga.ControllerSettings{
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
	comp := &saga.Component{Controls: map[string]saga.ControllerSettings{
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
		Controls: map[string]saga.ControllerSettings{"licenses": {"enabled": true}},
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
			t.Errorf("%s: upstream = %v, want %v, the component declares upstream and the "+
				"second repository overrides it", target.URL, target.Upstream, want[target.URL])
		}
	}
}

// A component's images are scanned for licenses too.
//
// Two repositories and two images, per the rule that one of anything proves the loop runs and two
// prove it does not collapse, and because a component holding both is the case this exists for: a
// license obligation inside an image was invisible while this planned repositories only.
func TestLicensesPlansImagesAsWellAsRepositories(t *testing.T) {
	comp := &saga.Component{
		Name: "analytics",
		Repositories: []saga.Repository{
			{URL: "https://github.com/acme/console.git"},
			{URL: "https://github.com/acme/console-shared.git"},
		},
		Images: []saga.Image{
			{Image: "ghcr.io/acme/console:4.2"},
			{Image: "docker.io/library/alpine:3.19", BuiltBy: saga.BuiltByUpstream},
		},
	}
	model := saga.Model{Config: saga.Config{
		Controls: map[string]saga.ControllerSettings{
			"licenses": {"enabled": true, "deny": []any{"AGPL-3.0-only"}},
		},
	}}

	jobs, err := Licenses{}.Plan(model, comp)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(jobs) != 4 {
		t.Fatalf("planned %d jobs, want one per repository and one per image", len(jobs))
	}

	var repos, images []string
	for _, job := range jobs {
		// The same policy reaches every job. Which licenses a release may carry is a decision
		// about the release, not about where the code happens to sit.
		deny, _ := job.Config["deny"].([]string)
		if len(deny) != 1 || deny[0] != "AGPL-3.0-only" {
			t.Errorf("job carries deny=%v, want the component's policy", job.Config["deny"])
		}
		switch target := job.Target.(type) {
		case plugin.RepositoryTarget:
			repos = append(repos, target.URL)
		case plugin.ImageTarget:
			images = append(images, target.Ref)
			// Who publishes it travels with the image, so a license in one somebody else builds
			// is not reported as something to change here.
			if want := target.Ref == "docker.io/library/alpine:3.19"; target.Upstream != want {
				t.Errorf("%s: upstream = %v, want %v", target.Ref, target.Upstream, want)
			}
		default:
			t.Errorf("unexpected target %T", job.Target)
		}
	}
	if len(repos) != 2 || len(images) != 2 {
		t.Errorf("planned %d repositories and %d images, want two of each", len(repos), len(images))
	}
}

// A component with images and no repositories still gets scanned. It is the ordinary shape for
// something a team runs and does not build, and it is exactly where the source tree is unavailable
// to answer the license question by hand.
func TestLicensesScansAComponentThatOnlyRunsImages(t *testing.T) {
	jobs, err := Licenses{}.Plan(
		saga.Model{Config: saga.Config{
			Controls: map[string]saga.ControllerSettings{"licenses": {"enabled": true}},
		}},
		&saga.Component{Name: "vendor-console", BuiltBy: saga.BuiltByUpstream,
			Images: []saga.Image{{Image: "ghcr.io/vendor/console:4.2"}}})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("planned %d jobs, want one for the image", len(jobs))
	}
	target, ok := jobs[0].Target.(plugin.ImageTarget)
	if !ok || !target.Upstream {
		t.Errorf("target = %+v, want the image marked as somebody else's", jobs[0].Target)
	}
}

func TestLicensesScannerBlockAddsToThePolicy(t *testing.T) {
	// A scanner block tightens the control's policy like a component does. Replacing its list with
	// the control's would drop a license the scanner block denies whenever the control denies any.
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"licenses": {
			"deny":         []any{"GPL-3.0-only"},
			"trivyLicense": map[string]any{"deny": []any{"Sleepycat", "GPL-3.0-only"}, "warn": []any{"MPL-2.0"}},
		},
	}}}
	comp := &saga.Component{Name: "c", Repositories: []saga.Repository{{URL: "https://git/a"}}}
	jobs, err := Licenses{}.Plan(model, comp)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("Plan = %v, %v; want one job", jobs, err)
	}
	cfg := jobs[0].Config
	if deny, _ := cfg["deny"].([]string); strings.Join(deny, ",") != "GPL-3.0-only,Sleepycat" {
		t.Errorf("deny = %v, want the control's and the scanner block's, deduplicated", cfg["deny"])
	}
	if warn := settingStrings(saga.ControllerSettings(cfg), "warn"); strings.Join(warn, ",") != "MPL-2.0" {
		t.Errorf("warn = %v, want the scanner block's own list where the control sets none", cfg["warn"])
	}
}

// Each job names the settings that listed each license: the project's list, the component's own,
// and the scanner block the job merged, which is the component's when it writes one.
func TestLicensesPlanNamesWhereEachLicenseWasListed(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"licenses": {
			"deny":         []any{"GPL-3.0-only"},
			"trivyLicense": map[string]any{"deny": []any{"SSPL-1.0"}, "denyFrom": map[string]any{"SSPL-1.0": "anything"}},
		},
	}}}
	api := &saga.Component{Name: "api",
		Repositories: []saga.Repository{{URL: "https://git/a"}, {URL: "https://git/b"}},
		Controls:     map[string]saga.ControllerSettings{"licenses": {"deny": []any{"Sleepycat"}}}}
	worker := &saga.Component{Name: "worker",
		Repositories: []saga.Repository{{URL: "https://git/c"}},
		Controls: map[string]saga.ControllerSettings{"licenses": {
			"deny":         []any{"GPL-3.0-only"},
			"trivyLicense": map[string]any{"warn": []any{"MPL-2.0"}},
		}}}
	for _, c := range []struct {
		comp       *saga.Component
		deny, warn map[string]any
	}{
		{api, map[string]any{
			"GPL-3.0-only": "config.controls.licenses.deny",
			"Sleepycat":    `components["api"].controls.licenses.deny`,
			"SSPL-1.0":     "config.controls.licenses.trivyLicense.deny",
		}, nil},
		{worker, map[string]any{
			"GPL-3.0-only": `config.controls.licenses.deny, components["worker"].controls.licenses.deny`,
			"SSPL-1.0":     "config.controls.licenses.trivyLicense.deny",
		}, map[string]any{
			"MPL-2.0": `components["worker"].controls.licenses.trivyLicense.warn`,
		}},
	} {
		jobs, err := Licenses{}.Plan(model, c.comp)
		if err != nil || len(jobs) != len(c.comp.Repositories) {
			t.Fatalf("%s: Plan = %v, %v", c.comp.Name, jobs, err)
		}
		for _, j := range jobs {
			if got, _ := j.Config["denyFrom"].(map[string]any); !reflect.DeepEqual(got, c.deny) {
				t.Errorf("%s: denyFrom = %v, want %v", c.comp.Name, j.Config["denyFrom"], c.deny)
			}
			if got, _ := j.Config["warnFrom"].(map[string]any); !reflect.DeepEqual(got, c.warn) {
				t.Errorf("%s: warnFrom = %v, want %v", c.comp.Name, j.Config["warnFrom"], c.warn)
			}
		}
	}
	// With no policy anywhere, a job carries no sources.
	jobs, _ := Licenses{}.Plan(saga.Model{}, &saga.Component{Name: "c", Repositories: []saga.Repository{{URL: "https://git/a"}}})
	if _, ok := jobs[0].Config["denyFrom"]; ok {
		t.Errorf("config = %v, want no sources", jobs[0].Config)
	}
}

func TestLicensesValidateRefusesAPolicySourceKey(t *testing.T) {
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"licenses": {"trivyLicense": map[string]any{"denyFrom": map[string]any{}}},
		}},
		Components: []saga.Component{
			{Name: "api", Controls: map[string]saga.ControllerSettings{
				"licenses": {"mendLicenses": map[string]any{"warnFrom": map[string]any{}}},
			}},
			{Name: "worker", Controls: map[string]saga.ControllerSettings{
				"licenses": {"deny": []any{"GPL-3.0-only"}},
			}},
		},
	}
	var got []string
	for _, err := range (Licenses{}).Validate(model) {
		got = append(got, err.Error())
	}
	want := []string{
		`config.controls.licenses.trivyLicense: "denyFrom" is set by the control and cannot be written in a descriptor`,
		`components["api"].controls.licenses.mendLicenses: "warnFrom" is set by the control and cannot be written in a descriptor`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("problems = %q, want %q", got, want)
	}
}
