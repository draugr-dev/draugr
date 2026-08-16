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

// Discovery's promise is that the descriptor writes itself. One that enables no control has not
// written itself — it has written a shape, and its first scan reports PASS having checked
// nothing.
func TestEnableControlsForSurface(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		comp saga.Component
		want []string
	}{
		{"repositories", saga.Component{Repositories: []saga.Repository{{URL: "u"}}}, []string{"iac", "sast", "sca", "secrets"}},
		{"images", saga.Component{Images: []saga.Image{{Image: "nginx:1"}}}, []string{"images"}},
		{"infrastructure", saga.Component{Infrastructure: []saga.Infrastructure{{Kind: "kubernetes"}}}, []string{"infrastructure"}},

		// Passive host controls only. dast sends attack traffic at a live service, and enabling
		// that because a survey noticed the service exists is not discovery's decision to make.
		{"hosts", saga.Component{Hosts: []saga.Host{{URL: "https://x.test"}}}, []string{"headers", "tls"}},

		{"nothing discovered", saga.Component{Name: "empty"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &saga.Model{Components: []saga.Component{tc.comp}}
			got := EnableControls(m)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("enabled %v, want %v", got, tc.want)
			}
			for _, name := range tc.want {
				if m.Config.Controllers[name] == nil {
					t.Errorf("%s should be present in the descriptor", name)
				}
			}
			if tc.name == "hosts" && m.Config.Controllers["dast"] != nil {
				t.Error("dast must not be enabled by discovery")
			}
		})
	}
}

// --merge runs against a descriptor people edit. A survey that re-enabled something switched off
// by hand would be a worse failure than the one this fixes.
func TestEnableControlsLeavesConfiguredControlsAlone(t *testing.T) {
	t.Parallel()

	m := &saga.Model{
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"sca":     {"enabled": false},
			"secrets": {"enabled": true, "someOption": "kept"},
		}},
		Components: []saga.Component{{Repositories: []saga.Repository{{URL: "u"}}}},
	}
	added := EnableControls(m)

	if slices.Contains(added, "sca") || slices.Contains(added, "secrets") {
		t.Errorf("a configured control must be left alone, added %v", added)
	}
	if enabled, _ := m.Config.Controllers["sca"]["enabled"].(bool); enabled {
		t.Error("a control switched off by hand must stay off")
	}
	if m.Config.Controllers["secrets"]["someOption"] != "kept" {
		t.Error("an existing control's options must survive")
	}
	// The ones nobody mentioned are still filled in.
	if !slices.Equal(added, []string{"iac", "sast"}) {
		t.Errorf("added = %v, want [iac sast]", added)
	}
}
