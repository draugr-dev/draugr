package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestHeadersInfo(t *testing.T) {
	info := NewHeaders().Info()
	if info.Name != "headers" {
		t.Errorf("name = %q", info.Name)
	}
	if info.Scope != plugin.ScopeComponent {
		t.Errorf("scope = %v", info.Scope)
	}
}

func TestHeadersPlan(t *testing.T) {
	comp := &saga.Component{Name: "web", Hosts: []saga.Host{
		{Name: "ui", URL: "https://app.example.com", Type: "browser"},
		{Name: "gw", URL: "https://api.example.com", Type: "api"},
		{Name: "blank"}, // no URL → skipped
	}}
	jobs, err := NewHeaders().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs (blank host skipped), got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "http-headers" {
			t.Errorf("scanner = %q", j.Scanner)
		}
		if _, ok := j.Target.(plugin.HostTarget); !ok {
			t.Errorf("target = %T, want HostTarget", j.Target)
		}
	}
}

func TestHeadersPlanNilComponent(t *testing.T) {
	jobs, err := NewHeaders().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component should yield no jobs, got %v %v", jobs, err)
	}
}

func TestHeadersAggregate(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "http-headers", Results: []sarif.Result{
			{RuleID: "headers/csp-missing", Level: sarif.LevelWarning, Location: sarif.Location{URI: "https://a"}},
			{RuleID: "headers/server-disclosure", Level: sarif.LevelNote, Location: sarif.Location{URI: "https://a"}},
		}},
		{Tool: "http-headers", Results: []sarif.Result{
			{RuleID: "headers/cors-wildcard-with-credentials", Level: sarif.LevelError, Location: sarif.Location{URI: "https://b"}},
		}},
	}
	res, err := NewHeaders().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "headers" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 || res.Summary.Notes != 1 {
		t.Errorf("summary = %+v", res.Summary)
	}
}

func TestHeadersAggregateEmpty(t *testing.T) {
	res, err := NewHeaders().Aggregate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Errors+res.Summary.Warnings+res.Summary.Notes != 0 {
		t.Errorf("empty aggregate should have no findings, got %+v", res.Summary)
	}
}
