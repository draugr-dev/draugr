package surfaces

import (
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestUncoveredSurfacesNamesWhatNobodyChecks(t *testing.T) {
	// A descriptor declaring a host with the host controls off scans everything about that
	// component except the thing it exposes to the internet, and says nothing.
	model := &saga.Model{
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"sca": {"enabled": true},
		}},
		Components: []saga.Component{
			{Name: "web", Repositories: []saga.Repository{{URL: "u"}}, Hosts: []saga.Host{{URL: "h"}}},
			{Name: "svc", Images: []saga.Image{{Image: "i"}}},
		},
	}
	got := Uncovered(model)
	want := []string{
		"web declares hosts, and headers, tls are not enabled",
		"svc declares images, and images is not enabled",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestUncoveredSurfacesTreatsPartialCoverAsCovered(t *testing.T) {
	// One enabled control means somebody is looking. Nagging about the rest would make the note
	// routine, and a routine note is one nobody reads.
	model := &saga.Model{
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"headers": {"enabled": true},
		}},
		Components: []saga.Component{{Name: "web", Hosts: []saga.Host{{URL: "h"}}}},
	}
	if got := Uncovered(model); len(got) != 0 {
		t.Errorf("partial cover is cover: %q", got)
	}
}

func TestUncoveredSurfacesRespectsAPerComponentOverride(t *testing.T) {
	// A control enabled on the component alone still counts as looking.
	model := &saga.Model{
		Components: []saga.Component{{
			Name:        "svc",
			Images:      []saga.Image{{Image: "i"}},
			Controllers: map[string]saga.ControllerSettings{"images": {"enabled": true}},
		}},
	}
	if got := Uncovered(model); len(got) != 0 {
		t.Errorf("a per-component enable is still enabled: %q", got)
	}
}

func TestUncoveredSurfacesIsSilentWhenEverythingIsCovered(t *testing.T) {
	model := &saga.Model{
		Config:     saga.Config{Controllers: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{{Name: "web", Repositories: []saga.Repository{{URL: "u"}}}},
	}
	if got := Uncovered(model); len(got) != 0 {
		t.Errorf("nothing to say: %q", got)
	}
}

func TestDeclaresHostsIsWhatDecidesTheDastCaveat(t *testing.T) {
	// The caveat is only worth printing when there is a host to attack; on a repository-only
	// descriptor it answers a question nobody asked.
	withHost := &saga.Model{Components: []saga.Component{{Name: "web", Hosts: []saga.Host{{URL: "h"}}}}}
	if !DeclaresHosts(withHost) {
		t.Error("a declared host should be reported")
	}
	repoOnly := &saga.Model{Components: []saga.Component{{Name: "lib", Repositories: []saga.Repository{{URL: "u"}}}}}
	if DeclaresHosts(repoOnly) {
		t.Error("no host declared, so nothing to caveat")
	}
}

func TestComponentHasRejectsASurfaceThatDoesNotExist(t *testing.T) {
	// Controls is the only source of surface names; an unknown one must not read as declared,
	// because a "yes" here would put a component into the uncovered list for a surface it has no
	// way to cover.
	c := &saga.Component{Name: "svc", Images: []saga.Image{{Image: "i"}}}
	if ComponentHas(c, "endpoints") {
		t.Error("an unknown surface is not declared")
	}
}
