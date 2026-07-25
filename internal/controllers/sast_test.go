package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestSASTInfo(t *testing.T) {
	if NewSAST().Info().Name != "sast" {
		t.Error("name should be sast")
	}
}

func TestSASTPlan(t *testing.T) {
	comp := &saga.Component{Name: "backend", Repositories: []saga.Repository{
		{URL: "https://git/a.git", Revision: "main"},
		{URL: "https://git/b.git"},
	}}
	jobs, err := NewSAST().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "semgrep" {
			t.Errorf("scanner = %q", j.Scanner)
		}
	}
}

func TestSASTPlanGosecOptIn(t *testing.T) {
	// A component enabling gosec gets one job per repo per scanner (semgrep default + gosec).
	comp := &saga.Component{
		Name:         "backend",
		Repositories: []saga.Repository{{URL: "https://git/a.git"}},
		Controllers: map[string]saga.ControllerSettings{
			"sast": {"gosec": map[string]any{"enabled": true}},
		},
	}
	jobs, err := NewSAST().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, j := range jobs {
		got[j.Scanner] = true
	}
	if len(jobs) != 2 || !got["semgrep"] || !got["gosec"] {
		t.Fatalf("want semgrep+gosec jobs, got %+v", jobs)
	}
}

func TestSASTPlanProjectGosecOptIn(t *testing.T) {
	// Project-level gosec opt-in applies when the component has no override.
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"sast": {"gosec": map[string]any{"enabled": true}},
	}}}
	comp := &saga.Component{Name: "backend", Repositories: []saga.Repository{{URL: "https://git/a.git"}}}
	jobs, err := NewSAST().Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, j := range jobs {
		got[j.Scanner] = true
	}
	if len(jobs) != 2 || !got["semgrep"] || !got["gosec"] {
		t.Fatalf("want semgrep+gosec jobs, got %+v", jobs)
	}
}

func TestSASTPlanSemgrepConfigPassthrough(t *testing.T) {
	// A semgrep config block flows into the job's Config.
	comp := &saga.Component{
		Name:         "backend",
		Repositories: []saga.Repository{{URL: "https://git/a.git"}},
		Controllers: map[string]saga.ControllerSettings{
			"sast": {"semgrep": map[string]any{"config": "p/owasp-top-ten"}},
		},
	}
	jobs, err := NewSAST().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Scanner != "semgrep" {
		t.Fatalf("want a single semgrep job, got %+v", jobs)
	}
	if jobs[0].Config["config"] != "p/owasp-top-ten" {
		t.Errorf("config not passed through: %+v", jobs[0].Config)
	}
}

func TestSASTPlanDefaultConfigNil(t *testing.T) {
	// With no config, the default semgrep job carries no config.
	comp := &saga.Component{Name: "c", Repositories: []saga.Repository{{URL: "u"}}}
	jobs, err := NewSAST().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Scanner != "semgrep" || jobs[0].Config != nil {
		t.Fatalf("want a single config-less semgrep job, got %+v", jobs)
	}
}

func TestSASTScannerSet(t *testing.T) {
	model := saga.Model{Components: []saga.Component{
		{Name: "a", Repositories: []saga.Repository{{URL: "u"}}},
		{Name: "b", Repositories: []saga.Repository{{URL: "u"}},
			Controllers: map[string]saga.ControllerSettings{
				"sast": {"gosec": map[string]any{"enabled": true}},
			}},
	}}
	set := SASTScannerSet(model)
	if !set["semgrep"] || !set["gosec"] || len(set) != 2 {
		t.Errorf("scanner set = %v, want {semgrep, gosec}", set)
	}
}

func TestSASTPlanNilComponent(t *testing.T) {
	jobs, err := NewSAST().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component should yield no jobs, got %v %v", jobs, err)
	}
}

func TestSASTAggregate(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "semgrep", Results: []sarif.Result{
			{RuleID: "go.lang.security.audit.xss", Level: sarif.LevelError, Location: sarif.Location{URI: "h.go"}},
			{RuleID: "go.lang.correctness.useless-eqeq", Level: sarif.LevelWarning, Location: sarif.Location{URI: "h.go"}},
			{RuleID: "generic.info", Level: sarif.LevelNote, Location: sarif.Location{URI: "h.go"}},
		}},
	}
	res, err := NewSAST().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "sast" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 || res.Summary.Notes != 1 {
		t.Fatalf("summary = %+v", res.Summary)
	}
}

func TestSASTAggregateEmpty(t *testing.T) {
	res, err := NewSAST().Aggregate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Errors != 0 || res.Summary.Warnings != 0 || res.Summary.Notes != 0 {
		t.Errorf("no reports should yield empty summary, got %+v", res.Summary)
	}
}
