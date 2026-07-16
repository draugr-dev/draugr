package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestImagesInfo(t *testing.T) {
	info := NewImages().Info()
	if info.Name != "images" {
		t.Errorf("name = %q", info.Name)
	}
}

func TestImagesPlan(t *testing.T) {
	c := NewImages()
	comp := &saga.Component{Name: "backend", Images: []saga.Image{
		{Image: "repo/a:1"}, {Image: "repo/b:2"},
	}}
	jobs, err := c.Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "trivy" {
			t.Errorf("scanner = %q", j.Scanner)
		}
	}
}

func TestImagesPlanCarriesDigest(t *testing.T) {
	jobs, err := NewImages().Plan(saga.Model{}, &saga.Component{Name: "backend", Images: []saga.Image{
		{Image: "repo/a:1", Digest: "sha256:abc"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	img, ok := jobs[0].Target.(plugin.ImageTarget)
	if !ok {
		t.Fatalf("target = %T, want ImageTarget", jobs[0].Target)
	}
	if img.Ref != "repo/a:1" || img.Digest != "sha256:abc" {
		t.Errorf("target = %+v, want ref+digest carried through", img)
	}
	// Identity is the digest, so the cache key is content-addressed.
	if img.Identity() != "sha256:abc" {
		t.Errorf("identity = %q, want digest", img.Identity())
	}
}

func TestImagesPlanNilComponent(t *testing.T) {
	jobs, err := NewImages().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component should yield no jobs, got %v %v", jobs, err)
	}
}

func TestImagesAggregate(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Location: sarif.Location{URI: "a"}},
			{RuleID: "CVE-2", Level: sarif.LevelWarning, Location: sarif.Location{URI: "a"}},
		}},
		{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-3", Level: sarif.LevelNote, Location: sarif.Location{URI: "b"}},
		}},
	}
	res, err := NewImages().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "images" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 || res.Summary.Notes != 1 {
		t.Fatalf("summary = %+v", res.Summary)
	}
}
