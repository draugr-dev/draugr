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

func TestSASTPlanComponentScanners(t *testing.T) {
	// A component opting into [semgrep, gosec] gets one job per repo per scanner.
	comp := &saga.Component{
		Name:         "backend",
		Repositories: []saga.Repository{{URL: "https://git/a.git"}},
		Controllers: map[string]saga.ControllerSettings{
			"sast": {"scanners": []any{"semgrep", "gosec"}},
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

func TestSASTPlanProjectScanners(t *testing.T) {
	// Project-level scanners apply when the component has no override.
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"sast": {"scanners": []any{"gosec"}},
	}}}
	comp := &saga.Component{Name: "backend", Repositories: []saga.Repository{{URL: "https://git/a.git"}}}
	jobs, err := NewSAST().Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Scanner != "gosec" {
		t.Fatalf("want a single gosec job, got %+v", jobs)
	}
}

func TestSASTScannersDefaultAndFallback(t *testing.T) {
	comp := &saga.Component{Name: "c", Repositories: []saga.Repository{{URL: "u"}}}
	// No config → default semgrep.
	if got := sastScanners(saga.Model{}, comp); len(got) != 1 || got[0] != "semgrep" {
		t.Errorf("default = %v, want [semgrep]", got)
	}
	// An empty / malformed scanners list falls back to the default rather than running nothing.
	comp.Controllers = map[string]saga.ControllerSettings{"sast": {"scanners": []any{}}}
	if got := sastScanners(saga.Model{}, comp); len(got) != 1 || got[0] != "semgrep" {
		t.Errorf("empty list = %v, want fallback [semgrep]", got)
	}
	comp.Controllers = map[string]saga.ControllerSettings{"sast": {"scanners": "notalist"}}
	if got := sastScanners(saga.Model{}, comp); len(got) != 1 || got[0] != "semgrep" {
		t.Errorf("non-list = %v, want fallback [semgrep]", got)
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
