package saga

import "testing"

// A component described in two fragments is one component, and the surfaces add up rather than
// one replacing the other — the overlay a split descriptor depends on.
func TestUpsertComponentUnionsSurfaces(t *testing.T) {
	comps := UpsertComponent(nil, Component{Name: "web", Repositories: []Repository{{URL: "r"}}})
	comps = UpsertComponent(comps, Component{Name: "web", Images: []Image{{Image: "i"}}})

	if len(comps) != 1 {
		t.Fatalf("components = %d, want 1", len(comps))
	}
	if len(comps[0].Repositories) != 1 || len(comps[0].Images) != 1 {
		t.Errorf("surfaces not unioned: %+v", comps[0])
	}
}

// Scalars come from the component already present. This is what keeps the root descriptor
// authoritative about classification when a fragment describes the same component.
func TestUpsertComponentKeepsTheFirstClassification(t *testing.T) {
	comps := UpsertComponent(nil, Component{Name: "web", Exposure: "internal", Criticality: "supporting"})
	comps = UpsertComponent(comps, Component{Name: "web", Exposure: "public", Criticality: "critical"})

	if comps[0].Exposure != "internal" || comps[0].Criticality != "supporting" {
		t.Errorf("a later fragment reclassified the component: %+v", comps[0])
	}
}

func TestUnionDedup(t *testing.T) {
	hosts := unionHosts([]Host{{URL: "x"}}, []Host{{URL: "x"}, {URL: "y"}})
	if len(hosts) != 2 {
		t.Errorf("hosts = %d, want 2", len(hosts))
	}
	if imgs := unionImages([]Image{{Image: "a"}}, []Image{{Image: "a"}}); len(imgs) != 1 {
		t.Errorf("images = %d, want 1", len(imgs))
	}
	repos := unionRepositories([]Repository{{URL: "r"}}, []Repository{{URL: "r"}, {URL: "r", Revision: "v2"}})
	if len(repos) != 2 {
		t.Errorf("repositories = %d, want 2 — a revision is part of a repository's identity", len(repos))
	}
}

// Exclusions from a fragment add to the descriptor's rather than replacing them.
func TestMergeAppendsExclusions(t *testing.T) {
	m := &Model{Config: Config{Exclude: []ExcludeRule{{Rules: []string{"A"}, Reason: "r"}}}}
	Merge(m, Fragment{Config: FragmentConfig{Exclude: []ExcludeRule{{Rules: []string{"B"}, Reason: "r"}}}})
	if len(m.Config.Exclude) != 2 {
		t.Errorf("exclusions = %d, want 2", len(m.Config.Exclude))
	}
}
