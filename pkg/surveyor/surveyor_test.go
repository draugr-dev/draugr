package surveyor

import (
	"context"
	"errors"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

type fakeSurveyor struct {
	name string
	frag saga.Fragment
	err  error
}

func (f fakeSurveyor) Info() plugin.SurveyorInfo { return plugin.SurveyorInfo{Name: f.name} }
func (f fakeSurveyor) Survey(context.Context, plugin.SurveyScope) (saga.Fragment, error) {
	return f.frag, f.err
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeSurveyor{name: "k8s"})
	r.Register(fakeSurveyor{name: "github"})
	if got := r.Names(); len(got) != 2 || got[0] != "github" || got[1] != "k8s" {
		t.Fatalf("names = %v (want sorted)", got)
	}
	if _, ok := r.Get("k8s"); !ok {
		t.Error("k8s should be registered")
	}
	if _, ok := r.Get("nope"); ok {
		t.Error("unknown surveyor should not be found")
	}
}

func TestRunMergesFragments(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeSurveyor{name: "a", frag: saga.Fragment{Components: []saga.Component{
		{Name: "web", Images: []saga.Image{{Image: "web:1"}}},
	}}})
	r.Register(fakeSurveyor{name: "b", frag: saga.Fragment{Components: []saga.Component{
		{Name: "web", Images: []saga.Image{{Image: "web:2"}}},
		{Name: "api", Hosts: []saga.Host{{URL: "https://api"}}},
	}}})

	frag, err := r.Run(context.Background(), []Request{{Surveyor: "a"}, {Surveyor: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.Components) != 2 {
		t.Fatalf("want 2 merged components, got %d", len(frag.Components))
	}
	// "web" should have both images unioned.
	for _, c := range frag.Components {
		if c.Name == "web" && len(c.Images) != 2 {
			t.Errorf("web images = %d, want 2 unioned", len(c.Images))
		}
	}
}

func TestRunCollectsErrors(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeSurveyor{name: "boom", err: errors.New("failed")})
	_, err := r.Run(context.Background(), []Request{{Surveyor: "boom"}, {Surveyor: "missing"}})
	if err == nil {
		t.Fatal("expected errors for failure + missing surveyor")
	}
}

func TestMergeFragmentsUnionsSurface(t *testing.T) {
	a := saga.Fragment{Components: []saga.Component{{
		Name:         "svc",
		Repositories: []saga.Repository{{URL: "u", Revision: "1"}},
		Kubernetes:   []saga.ClusterRef{{Cluster: "prod"}},
	}}}
	b := saga.Fragment{Components: []saga.Component{{
		Name:         "svc",
		Repositories: []saga.Repository{{URL: "u", Revision: "1"}}, // dup
		Kubernetes:   []saga.ClusterRef{{Cluster: "dev"}},
	}}}
	merged := MergeFragments(a, b)
	if len(merged.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(merged.Components))
	}
	c := merged.Components[0]
	if len(c.Repositories) != 1 {
		t.Errorf("repos should dedup to 1, got %d", len(c.Repositories))
	}
	if len(c.Kubernetes) != 2 {
		t.Errorf("infra should union to 2, got %d", len(c.Kubernetes))
	}
}

func TestApplyIntoModel(t *testing.T) {
	model := &saga.Model{Components: []saga.Component{
		{Name: "web", Hosts: []saga.Host{{URL: "https://web"}}},
	}}
	Apply(model, saga.Fragment{Components: []saga.Component{
		{Name: "web", Images: []saga.Image{{Image: "web:1"}}}, // merge into existing
		{Name: "new", Images: []saga.Image{{Image: "new:1"}}}, // added
	}})
	if len(model.Components) != 2 {
		t.Fatalf("want 2 components, got %d", len(model.Components))
	}
	for _, c := range model.Components {
		if c.Name == "web" && (len(c.Hosts) != 1 || len(c.Images) != 1) {
			t.Errorf("web should have host + image after apply: %+v", c)
		}
	}
}

// A fragment's exposure reasons have to survive the merge.
//
// The merge is the only path from a surveyor to the descriptor, so anything it drops may as well
// never have been discovered. And dropping this is invisible: the exposure still arrives, the
// file is still written, and the only thing missing is the evidence for a value the reader is
// being asked to confirm.
func TestMergeFragmentsKeepsWhyEachExposureWasProposed(t *testing.T) {
	merged := MergeFragments(
		saga.Fragment{
			Components:      []saga.Component{{Name: "front", Exposure: saga.ExposurePublic}},
			ExposureReasons: map[string]string{"front": "an Ingress routes into it"},
		},
		saga.Fragment{
			Components:      []saga.Component{{Name: "back", Exposure: saga.ExposureInternal}},
			ExposureReasons: map[string]string{"back": "no Ingress, external Service or NetworkPolicy found"},
		},
	)
	if len(merged.ExposureReasons) != 2 {
		t.Fatalf("reasons = %v, want one per component", merged.ExposureReasons)
	}
	if merged.ExposureReasons["front"] != "an Ingress routes into it" {
		t.Errorf("front lost its reason: %q", merged.ExposureReasons["front"])
	}
}

// The surface unions but a proposed value does not, so the reason has to stay with the value that
// stayed, otherwise a component ends up carrying one fragment's exposure and another's reason.
func TestMergeFragmentsKeepsTheReasonBelongingToTheExposureItKept(t *testing.T) {
	merged := MergeFragments(
		saga.Fragment{
			Components:      []saga.Component{{Name: "app", Exposure: saga.ExposurePublic}},
			ExposureReasons: map[string]string{"app": "an Ingress routes into it"},
		},
		saga.Fragment{
			Components:      []saga.Component{{Name: "app", Exposure: saga.ExposureInternal}},
			ExposureReasons: map[string]string{"app": "no Ingress, external Service or NetworkPolicy found"},
		},
	)
	if got := merged.ExposureReasons["app"]; got != "an Ingress routes into it" {
		t.Errorf("reason = %q, want the one belonging to the exposure that was kept", got)
	}
}

// Two surveys merge their clusters by name, and the first definition and the first reason for a
// proposal win, the same rule the components follow: a value already proposed is the one that
// stays, so its reason has to stay with it.
func TestMergeFragmentsKeepsTheFirstClusterAndReason(t *testing.T) {
	a := saga.Fragment{
		Clusters:        map[string]saga.Cluster{"prod": {Context: "prod-admin"}},
		ExposureReasons: map[string]string{"svc": "an Ingress routes into it"},
		SignerReasons:   map[string]string{"acme-ci": "read from ghcr.io/acme/api:1.0"},
	}
	b := saga.Fragment{
		Clusters:        map[string]saga.Cluster{"prod": {Context: "other"}, "dev": {Context: "dev"}},
		ExposureReasons: map[string]string{"svc": "a LoadBalancer Service", "web": "an Ingress"},
		SignerReasons:   map[string]string{"acme-ci": "read elsewhere", "chainguard": "read from cgr.dev"},
	}
	m := MergeFragments(a, b)
	if m.Clusters["prod"].Context != "prod-admin" || m.Clusters["dev"].Context != "dev" {
		t.Errorf("clusters = %+v, want prod from the first survey and dev added", m.Clusters)
	}
	if m.ExposureReasons["svc"] != "an Ingress routes into it" || m.ExposureReasons["web"] != "an Ingress" {
		t.Errorf("exposure reasons = %v", m.ExposureReasons)
	}
	if m.SignerReasons["acme-ci"] != "read from ghcr.io/acme/api:1.0" || m.SignerReasons["chainguard"] == "" {
		t.Errorf("signer reasons = %v", m.SignerReasons)
	}
}
