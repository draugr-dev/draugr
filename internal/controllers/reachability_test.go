package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func scaJobsFor(t *testing.T, model saga.Model) []string {
	t.Helper()
	comp := &saga.Component{Name: "api", Repositories: []saga.Repository{{URL: "."}}}
	model.Components = []saga.Component{*comp}
	jobs, err := SCA{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, j := range jobs {
		names = append(names, j.Scanner)
	}
	return names
}

func TestReachabilityAnalyzerIsPlannedFromConfigNotTheScannerBlock(t *testing.T) {
	got := scaJobsFor(t, saga.Model{Config: saga.Config{
		Reachability: &saga.ReachabilityConfig{Analyzers: []string{"govulncheck"}},
	}})
	if len(got) != 2 || got[0] != "trivy-fs" || got[1] != "govulncheck" {
		t.Fatalf("jobs = %v, want the manifest scanner and the analyzer", got)
	}
}

func TestReachabilityAnalyzerIsNeverSelectedFromAScannerBlock(t *testing.T) {
	// The descriptor is rejected at load, but planning must not honor it either: a second way to
	// enable something that ranks findings down is a way somebody enables it without meaning to.
	got := scaJobsFor(t, saga.Model{Config: saga.Config{
		Controllers: map[string]saga.ControllerSettings{
			"sca": {"govulncheck": saga.ControllerSettings{"enabled": true}},
		},
	}})
	for _, name := range got {
		if name == "govulncheck" {
			t.Fatalf("jobs = %v, analyzer selected from a scanner block", got)
		}
	}
}

func TestReachabilityConfigIgnoresWhatIsNotAnAnalyzer(t *testing.T) {
	// A name that is not an analyzer is rejected by validation; planning must not turn it into a
	// job it cannot run either.
	got := scaJobsFor(t, saga.Model{Config: saga.Config{
		Reachability: &saga.ReachabilityConfig{Analyzers: []string{"trivy-fs", "nonsense"}},
	}})
	if len(got) != 1 || got[0] != "trivy-fs" {
		t.Fatalf("jobs = %v, want only the default scanner", got)
	}
}

func TestReachabilityAnalyzersAreDeduplicatedAndOrdered(t *testing.T) {
	got := scaJobsFor(t, saga.Model{Config: saga.Config{
		Reachability: &saga.ReachabilityConfig{Analyzers: []string{"govulncheck", "govulncheck"}},
	}})
	if len(got) != 2 {
		t.Fatalf("jobs = %v, want the analyzer planned once", got)
	}
}

func TestNoReachabilityConfigPlansNoAnalyzer(t *testing.T) {
	got := scaJobsFor(t, saga.Model{})
	if len(got) != 1 || got[0] != "trivy-fs" {
		t.Fatalf("jobs = %v, want only the default scanner", got)
	}
}
