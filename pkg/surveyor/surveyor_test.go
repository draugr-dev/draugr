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
		Name:           "svc",
		Repositories:   []saga.Repository{{URL: "u", Revision: "1"}},
		Infrastructure: []saga.Infrastructure{{Kind: "kubernetes", Ref: "prod"}},
	}}}
	b := saga.Fragment{Components: []saga.Component{{
		Name:           "svc",
		Repositories:   []saga.Repository{{URL: "u", Revision: "1"}}, // dup
		Infrastructure: []saga.Infrastructure{{Kind: "kubernetes", Ref: "dev"}},
	}}}
	merged := MergeFragments(a, b)
	if len(merged.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(merged.Components))
	}
	c := merged.Components[0]
	if len(c.Repositories) != 1 {
		t.Errorf("repos should dedup to 1, got %d", len(c.Repositories))
	}
	if len(c.Infrastructure) != 2 {
		t.Errorf("infra should union to 2, got %d", len(c.Infrastructure))
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

func TestUnionHostsAndImagesDedup(t *testing.T) {
	hosts := unionHosts([]saga.Host{{URL: "x"}}, []saga.Host{{URL: "x"}, {URL: "y"}})
	if len(hosts) != 2 {
		t.Errorf("hosts = %d, want 2", len(hosts))
	}
	imgs := unionImages([]saga.Image{{Image: "a"}}, []saga.Image{{Image: "a"}})
	if len(imgs) != 1 {
		t.Errorf("images = %d, want 1", len(imgs))
	}
}
