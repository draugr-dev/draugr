package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestSCAInfo(t *testing.T) {
	if NewSCA().Info().Name != "sca" {
		t.Error("name should be sca")
	}
}

func TestSCAPlan(t *testing.T) {
	comp := &saga.Component{Name: "backend", Repositories: []saga.Repository{
		{URL: "https://git/a.git", Revision: "main"},
		{URL: "https://git/b.git"},
	}}
	jobs, err := NewSCA().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "trivy-fs" {
			t.Errorf("scanner = %q", j.Scanner)
		}
		if j.CacheKey == "" {
			t.Error("job should carry a cache key")
		}
	}
}

func TestSCAPlanNilComponent(t *testing.T) {
	jobs, err := NewSCA().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component should yield no jobs, got %v %v", jobs, err)
	}
}

func TestSCAAggregate(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "trivy-fs", Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Location: sarif.Location{URI: "go.mod"}},
			{RuleID: "CVE-2", Level: sarif.LevelWarning, Location: sarif.Location{URI: "go.mod"}},
		}},
	}
	res, err := NewSCA().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "sca" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 {
		t.Fatalf("summary = %+v", res.Summary)
	}
}
