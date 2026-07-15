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
