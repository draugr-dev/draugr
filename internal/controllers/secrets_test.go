package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestSecretsInfo(t *testing.T) {
	info := NewSecrets().Info()
	if info.Name != "secrets" {
		t.Errorf("name = %q", info.Name)
	}
}

func TestSecretsPlan(t *testing.T) {
	comp := &saga.Component{Name: "backend", Repositories: []saga.Repository{
		{URL: "https://git/a.git", Revision: "main"},
		{URL: "https://git/b.git"},
	}}
	jobs, err := NewSecrets().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "gitleaks" {
			t.Errorf("scanner = %q", j.Scanner)
		}
		if j.CacheKey == "" {
			t.Error("job should carry a cache key")
		}
	}
}

func TestSecretsPlanNilComponent(t *testing.T) {
	jobs, err := NewSecrets().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component should yield no jobs, got %v %v", jobs, err)
	}
}

// A leaked secret must fail the gate no matter how the scanner rated it, so Aggregate
// escalates every finding to error severity.
func TestSecretsAggregateEscalatesToError(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "gitleaks", Results: []sarif.Result{
			{RuleID: "aws-key", Level: sarif.LevelWarning, Location: sarif.Location{URI: "config.yaml"}},
			{RuleID: "generic-token", Level: sarif.LevelNote, Location: sarif.Location{URI: ".env"}},
		}},
	}
	res, err := NewSecrets().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "secrets" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 2 || res.Summary.Warnings != 0 || res.Summary.Notes != 0 {
		t.Fatalf("all findings should be escalated to error; summary = %+v", res.Summary)
	}
	for _, r := range res.Report.Results {
		if r.Level != sarif.LevelError {
			t.Errorf("finding %q level = %q, want error", r.RuleID, r.Level)
		}
	}
}

func TestSecretsAggregateEmpty(t *testing.T) {
	res, err := NewSecrets().Aggregate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Errors != 0 {
		t.Errorf("no reports should yield no errors, got %+v", res.Summary)
	}
}
