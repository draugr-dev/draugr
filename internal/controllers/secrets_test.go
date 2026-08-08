package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
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

// The five controllers that named their scanner directly discarded the descriptor's block before
// anything could look at it: an option written there neither took effect nor was reported, and
// the scanner's declared schema — which exists to make that an error — was never consulted.
func TestSecretsPassesTheScannerBlockThrough(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"secrets": {"gitleaks": saga.ControllerSettings{"someOption": "value"}},
	}}}
	comp := &saga.Component{Name: "api", Repositories: []saga.Repository{{URL: "u"}}}
	jobs, err := Secrets{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	if jobs[0].Config["someOption"] != "value" {
		t.Errorf("config = %v, want the descriptor's block", jobs[0].Config)
	}
}

// And `enabled: false` on the only scanner now means what it says.
func TestSecretsHonoursADisabledScanner(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"secrets": {"gitleaks": saga.ControllerSettings{"enabled": false}},
	}}}
	comp := &saga.Component{Name: "api", Repositories: []saga.Repository{{URL: "u"}}}
	jobs, err := Secrets{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Errorf("got %d jobs, want none: a disabled scanner ran anyway", len(jobs))
	}
}

// Two repositories, because one proves the loop runs and two prove it does not collapse.
func TestSecretsPlansOneJobPerRepositoryWithConfig(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"secrets": {"gitleaks": saga.ControllerSettings{"someOption": "value"}},
	}}}
	comp := &saga.Component{Name: "api", Repositories: []saga.Repository{{URL: "a"}, {URL: "b"}}}
	jobs, err := Secrets{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d jobs, want 2", len(jobs))
	}
	seen := map[string]bool{}
	for _, j := range jobs {
		seen[j.Target.(plugin.RepositoryTarget).URL] = true
		if j.Config["someOption"] != "value" {
			t.Errorf("job for %v lost its config", j.Target)
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Errorf("both repositories should be planned, got %v", seen)
	}
}
