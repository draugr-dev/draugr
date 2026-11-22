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
	}
}

// osvScanner runs only where a descriptor turns it on, beside Trivy, once per repository, under its
// camelCase key.
func TestSCAPlansOSVScannerOnlyWhereTurnedOn(t *testing.T) {
	comp := &saga.Component{Name: "backend", Repositories: []saga.Repository{
		{URL: "https://git/a.git", Revision: "main"},
		{URL: "https://git/b.git"},
	}}
	jobs, err := NewSCA().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range jobs {
		if j.Scanner == "osv-scanner" {
			t.Fatal("osv-scanner planned for a descriptor that never names it")
		}
	}

	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"sca": {"osvScanner": map[string]any{"enabled": true}},
	}}}
	jobs, err = NewSCA().Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, j := range jobs {
		got[j.Scanner] = append(got[j.Scanner], j.Target.(interface{ Source() string }).Source())
	}
	if len(jobs) != 4 || len(got["trivy-fs"]) != 2 || len(got["osv-scanner"]) != 2 || got["osv-scanner"][0] == got["osv-scanner"][1] {
		t.Errorf("jobs = %v, want trivy-fs and osv-scanner over each repository", got)
	}
	if ScannerConfigKey("osv-scanner") != "osvScanner" {
		t.Errorf("key = %q", ScannerConfigKey("osv-scanner"))
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
