package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestIACInfo(t *testing.T) {
	if NewIAC().Info().Name != "iac" {
		t.Error("name should be iac")
	}
}

func TestIACPlan(t *testing.T) {
	comp := &saga.Component{Name: "infra", Repositories: []saga.Repository{
		{URL: "https://git/a.git", Revision: "main"},
		{URL: "https://git/b.git"},
	}}
	jobs, err := NewIAC().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "trivy-config" {
			t.Errorf("scanner = %q", j.Scanner)
		}
	}
}

func TestIACPlanNilComponent(t *testing.T) {
	jobs, err := NewIAC().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component should yield no jobs, got %v %v", jobs, err)
	}
}

func TestIACAggregate(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "trivy-config", Results: []sarif.Result{
			{RuleID: "AVD-AWS-0001", Level: sarif.LevelError, Location: sarif.Location{URI: "main.tf"}},
			{RuleID: "DS002", Level: sarif.LevelWarning, Location: sarif.Location{URI: "Dockerfile"}},
		}},
	}
	res, err := NewIAC().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "iac" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 {
		t.Fatalf("summary = %+v", res.Summary)
	}
}

func TestIACAggregateEmpty(t *testing.T) {
	res, err := NewIAC().Aggregate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Errors != 0 || res.Summary.Warnings != 0 || res.Summary.Notes != 0 {
		t.Errorf("no reports should yield empty summary, got %+v", res.Summary)
	}
}
