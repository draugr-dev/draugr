package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestDASTInfo(t *testing.T) {
	info := NewDAST().Info()
	if info.Name != "dast" {
		t.Errorf("name = %q", info.Name)
	}
	if info.Scope != plugin.ScopeComponent {
		t.Errorf("scope = %v", info.Scope)
	}
	if len(info.DefaultScanners) != 1 || info.DefaultScanners[0] != "nuclei" {
		t.Errorf("defaultScanners = %v", info.DefaultScanners)
	}
}

func TestDASTPlan(t *testing.T) {
	comp := &saga.Component{Name: "web", Hosts: []saga.Host{
		{Name: "ui", URL: "https://app.example.com", Type: "browser"},
		{Name: "gw", URL: "https://api.example.com", Type: "api"},
		{Name: "blank"}, // no URL → skipped
	}}
	jobs, err := NewDAST().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs (blank host skipped), got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "nuclei" {
			t.Errorf("scanner = %q", j.Scanner)
		}
		host, ok := j.Target.(plugin.HostTarget)
		if !ok {
			t.Errorf("target = %T, want HostTarget", j.Target)
			continue
		}
		if host.URL == "" {
			t.Error("job target has no URL")
		}
	}
}

func TestDASTPlanNilComponent(t *testing.T) {
	jobs, err := NewDAST().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component should yield no jobs, got %v %v", jobs, err)
	}
}

func TestDASTAggregate(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "nuclei", Results: []sarif.Result{
			{RuleID: "crit", Level: sarif.LevelError, Location: sarif.Location{URI: "https://a"}},
			{RuleID: "med", Level: sarif.LevelWarning, Location: sarif.Location{URI: "https://a"}},
		}},
		{Tool: "nuclei", Results: []sarif.Result{
			{RuleID: "info", Level: sarif.LevelNote, Location: sarif.Location{URI: "https://b"}},
		}},
	}
	res, err := NewDAST().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "dast" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 || res.Summary.Notes != 1 {
		t.Errorf("summary = %+v", res.Summary)
	}
}

func TestDASTAggregateEmpty(t *testing.T) {
	res, err := NewDAST().Aggregate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Errors+res.Summary.Warnings+res.Summary.Notes != 0 {
		t.Errorf("empty aggregate should have no findings, got %+v", res.Summary)
	}
}
