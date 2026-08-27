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
	comps := UpsertComponent(nil, Component{Name: "web", Exposure: Unstated(Exposure("internal")), Criticality: Unstated(Criticality("supporting"))})
	comps = UpsertComponent(comps, Component{Name: "web", Exposure: Unstated(Exposure("public")), Criticality: Unstated(Criticality("critical"))})

	if comps[0].Exposure.Value != "internal" || comps[0].Criticality.Value != "supporting" {
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

// A merge that matched an entry must not discard it. Dropping the newer one throws away whatever
// the later survey learned — a namespace scope, a digest, a narrowed path list — and the summary
// still counts the entry, so the loss is invisible: the file says what it said before and the
// command says it merged.
func TestMergeKeepsWhatALaterSurveyLearned(t *testing.T) {
	t.Run("an image gains the digest a survey resolved", func(t *testing.T) {
		got := UpsertComponent(
			[]Component{{Name: "api", Images: []Image{{Image: "acme/api:1.0"}}}},
			Component{Name: "api", Images: []Image{{Image: "acme/api:1.0", Digest: "sha256:abc"}}},
		)
		if d := got[0].Images[0].Digest; d != "sha256:abc" {
			t.Errorf("digest = %q, want the one the survey resolved", d)
		}
		if n := len(got[0].Images); n != 1 {
			t.Errorf("got %d images, want the one entry updated rather than duplicated", n)
		}
	})

	t.Run("a repository keeps both descriptions of its scope", func(t *testing.T) {
		got := UpsertComponent(
			[]Component{{Name: "api", Repositories: []Repository{{URL: "u", Paths: []string{"a"}}}}},
			Component{Name: "api", Repositories: []Repository{{URL: "u", Paths: []string{"b"}, Ignore: []string{"**/x/**"}}}},
		)
		r := got[0].Repositories[0]
		if len(r.Paths) != 2 {
			t.Errorf("paths = %v, want both", r.Paths)
		}
		if len(r.Ignore) != 1 {
			t.Errorf("ignore = %v, want the one the second survey carried", r.Ignore)
		}
	})

	t.Run("a host gains a name the first survey could not give it", func(t *testing.T) {
		got := UpsertComponent(
			[]Component{{Name: "api", Hosts: []Host{{URL: "https://a"}}}},
			Component{Name: "api", Hosts: []Host{{URL: "https://a", Name: "public", Type: "api"}}},
		)
		if got[0].Hosts[0].Name != "public" || got[0].Hosts[0].Type != "api" {
			t.Errorf("host = %+v, want the detail filled in", got[0].Hosts[0])
		}
	})
}

// Empty namespaces means the whole cluster, so it is the widest value rather than the identity.
// Merging a scoped survey into an unscoped entry must not narrow it: a descriptor that quietly
// starts scanning less than it did is the dangerous direction, and nobody re-reads a descriptor
// to check it still covers what it covered yesterday.
func TestMergeNeverNarrowsAClusterScope(t *testing.T) {
	whole := []Component{{Name: "c", Infrastructure: []Infrastructure{{Kind: "kubernetes", Ref: "c"}}}}
	scoped := Component{Name: "c", Infrastructure: []Infrastructure{
		{Kind: "kubernetes", Ref: "c", Namespaces: []string{"team-a"}},
	}}

	got := UpsertComponent(whole, scoped)
	if ns := got[0].Infrastructure[0].Namespaces; len(ns) != 0 {
		t.Errorf("namespaces = %v, want the whole cluster kept", ns)
	}

	// And the caller is told, because the flag the operator passed did not reach the descriptor.
	if n := NarrowsScope(&Model{Components: whole}, Fragment{Components: []Component{scoped}}); len(n) != 1 {
		t.Errorf("NarrowsScope = %v, want the target named", n)
	}
}

// Two scoped surveys union, because each names namespaces the other did not.
func TestMergeUnionsTwoScopedSurveys(t *testing.T) {
	got := UpsertComponent(
		[]Component{{Name: "c", Infrastructure: []Infrastructure{{Kind: "kubernetes", Ref: "c", Namespaces: []string{"a"}}}}},
		Component{Name: "c", Infrastructure: []Infrastructure{{Kind: "kubernetes", Ref: "c", Namespaces: []string{"b"}}}},
	)
	ns := got[0].Infrastructure[0].Namespaces
	if len(ns) != 2 || ns[0] != "a" || ns[1] != "b" {
		t.Errorf("namespaces = %v, want both", ns)
	}
	// Nothing was narrowed, so nothing should be reported.
	if n := NarrowsScope(
		&Model{Components: []Component{{Name: "c", Infrastructure: []Infrastructure{{Kind: "kubernetes", Ref: "c", Namespaces: []string{"a"}}}}}},
		Fragment{Components: []Component{{Name: "c", Infrastructure: []Infrastructure{{Kind: "kubernetes", Ref: "c", Namespaces: []string{"b"}}}}}},
	); len(n) != 0 {
		t.Errorf("NarrowsScope = %v, want nothing", n)
	}
}
