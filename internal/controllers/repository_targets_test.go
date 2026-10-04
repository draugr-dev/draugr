package controllers

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// repositoryControl is a control that plans a job per repository, with the model a case plans it
// under and the scanners that model selects.
type repositoryControl struct {
	name     string
	ctrl     plugin.Controller
	model    saga.Model
	scanners []string
}

// repositoryControls lists every control that scans a component's repositories, each under a
// model that selects more than one scanner where the control has a second to select.
func repositoryControls() []repositoryControl {
	return []repositoryControl{
		// A reachability analyzer plans as an sca job and reads the checkout the manifest scanner
		// reads, so it has to receive the same scope.
		{"sca", SCA{}, saga.Model{Config: saga.Config{
			Reachability: &saga.ReachabilityConfig{Analyzers: []string{govulncheckScanner}},
		}}, []string{trivyFSScanner, govulncheckScanner}},
		{"sast", SAST{}, saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"sast": {"gosec": map[string]any{"enabled": true}},
		}}}, []string{semgrepScanner, "gosec"}},
		{"secrets", Secrets{}, saga.Model{}, []string{gitleaksScanner}},
		{"iac", IAC{}, saga.Model{}, []string{trivyConfigScanner}},
		{"licenses", Licenses{}, saga.Model{}, []string{trivyLicenseScanner}},
	}
}

// Every control that scans a repository hands each job the target of the repository it was
// planned for.
//
// Two repositories, because one proves the loop runs and two prove it does not collapse. A target
// built from the first repository, or from the component, is right for one and wrong for the
// other. Every field differs between the two, so a field read from the wrong repository, or left
// out, fails on its own. Paths and Ignore decide what a scanner reads, and a job without them
// scans the whole tree and reports findings from parts the component does not claim.
func TestRepositoryControlsPlanEachRepositoryWithItsOwnTarget(t *testing.T) {
	const vendor, theme = "https://github.com/vendor/storefront.git", "https://github.com/acme/storefront-theme.git"
	comp := &saga.Component{
		Name:    "storefront",
		BuiltBy: saga.BuiltByUpstream,
		Repositories: []saga.Repository{
			{URL: vendor, Revision: "v4.2.0",
				Paths: []string{"cmd/storefront", "go.mod"}, Ignore: []string{"**/testdata/**"}},
			{URL: theme, Revision: "main",
				Paths: []string{"theme"}, Ignore: []string{"theme/vendor/"}, BuiltBy: saga.BuiltBySelf},
		},
	}
	want := map[string]plugin.RepositoryTarget{
		vendor: {URL: vendor, Revision: "v4.2.0",
			Paths: []string{"cmd/storefront", "go.mod"}, Ignore: []string{"**/testdata/**"}, Upstream: true},
		theme: {URL: theme, Revision: "main",
			Paths: []string{"theme"}, Ignore: []string{"theme/vendor/"}, Upstream: false},
	}

	for _, c := range repositoryControls() {
		t.Run(c.name, func(t *testing.T) {
			jobs, err := c.ctrl.Plan(c.model, comp)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			planned := map[string]int{}
			for _, j := range jobs {
				got, ok := j.Target.(plugin.RepositoryTarget)
				if !ok {
					t.Fatalf("%s: target is %T, want a repository", j.Scanner, j.Target)
				}
				if !reflect.DeepEqual(got, want[got.URL]) {
					t.Errorf("%s: target = %+v\nwant %+v", j.Scanner, got, want[got.URL])
				}
				planned[j.Scanner+" "+got.URL]++
			}
			for _, scanner := range c.scanners {
				for url := range want {
					if n := planned[scanner+" "+url]; n != 1 {
						t.Errorf("%s planned %d times against %s, want once", scanner, n, url)
					}
				}
			}
			if len(jobs) != len(c.scanners)*len(want) {
				t.Errorf("planned %d jobs, want one per scanner per repository (%d)",
					len(jobs), len(c.scanners)*len(want))
			}
		})
	}
}

// Two components on one repository, each scoped to its own part of it, are planned as two
// targets with two identities.
//
// A target that carries the shared URL and revision without the scope is one scan for both
// components, which reads neither component's part alone and files what it finds under each.
func TestRepositoryControlsKeepEachComponentsScopeOfASharedRepository(t *testing.T) {
	const mono = "https://github.com/acme/mono.git"
	web := &saga.Component{Name: "web", Repositories: []saga.Repository{
		{URL: mono, Revision: "v2", Paths: []string{"services/web"}},
	}}
	api := &saga.Component{Name: "api", Repositories: []saga.Repository{
		{URL: mono, Revision: "v2", Paths: []string{"services/api", "go.mod"}, Ignore: []string{"services/api/gen/"}},
	}}

	for _, c := range repositoryControls() {
		t.Run(c.name, func(t *testing.T) {
			identities := map[string]map[string]string{} // scanner → component → identity
			for _, comp := range []*saga.Component{web, api} {
				jobs, err := c.ctrl.Plan(c.model, comp)
				if err != nil {
					t.Fatalf("%s: plan: %v", comp.Name, err)
				}
				if len(jobs) != len(c.scanners) {
					t.Fatalf("%s: planned %d jobs, want one per scanner (%d)", comp.Name, len(jobs), len(c.scanners))
				}
				repo := comp.Repositories[0]
				for _, j := range jobs {
					got := j.Target.(plugin.RepositoryTarget)
					if !reflect.DeepEqual(got.Paths, repo.Paths) || !reflect.DeepEqual(got.Ignore, repo.Ignore) {
						t.Errorf("%s/%s: scope = paths %v, ignore %v, want paths %v, ignore %v",
							comp.Name, j.Scanner, got.Paths, got.Ignore, repo.Paths, repo.Ignore)
					}
					if identities[j.Scanner] == nil {
						identities[j.Scanner] = map[string]string{}
					}
					identities[j.Scanner][comp.Name] = got.Identity()
				}
			}
			for scanner, byComp := range identities {
				if byComp["web"] == byComp["api"] {
					t.Errorf("%s: both components identify as %q, so the engine runs one scan for both",
						scanner, byComp["web"])
				}
			}
		})
	}
}
