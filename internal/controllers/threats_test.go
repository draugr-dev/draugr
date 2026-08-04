package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestThreatsInfo(t *testing.T) {
	info := NewThreats().Info()
	if info.Name != "threats" || info.Scope != plugin.ScopeComponent {
		t.Errorf("Info() = %+v", info)
	}
	if len(info.DefaultScanners) != 1 || info.DefaultScanners[0] != urlhausScannerName {
		t.Errorf("default scanners = %v", info.DefaultScanners)
	}
}

func TestThreatsPlansOneLookupPerHost(t *testing.T) {
	comp := &saga.Component{Hosts: []saga.Host{
		{Name: "web", URL: "https://shop.example/"},
		{Name: "api", URL: "https://api.example/"},
	}}
	jobs, err := NewThreats().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != urlhausScannerName {
			t.Errorf("scanner = %q", j.Scanner)
		}
		if _, ok := j.Target.(plugin.HostTarget); !ok {
			t.Errorf("target = %T, want a host", j.Target)
		}
	}
}

func TestThreatsAsksAboutEachHostOnce(t *testing.T) {
	// The feed keys on the host, so two endpoints on one machine are one question. Asking twice
	// spends a rate limit to receive the same answer — and abuse.ch's is not generous.
	comp := &saga.Component{Hosts: []saga.Host{
		{Name: "web", URL: "https://shop.example/"},
		{Name: "checkout", URL: "https://shop.example/checkout"},
		{Name: "api", URL: "https://api.example/"},
	}}
	jobs, err := NewThreats().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Errorf("want one job per distinct host, got %d: %+v", len(jobs), jobs)
	}
}

func TestThreatsSkipsHostsWithNoURLAndNoComponent(t *testing.T) {
	jobs, err := NewThreats().Plan(saga.Model{}, &saga.Component{
		Hosts: []saga.Host{{Name: "unset"}, {Name: "web", URL: "https://x.example/"}},
	})
	if err != nil || len(jobs) != 1 {
		t.Errorf("jobs = %+v, err = %v", jobs, err)
	}
	if jobs, err := NewThreats().Plan(saga.Model{}, nil); err != nil || jobs != nil {
		t.Errorf("a nil component should plan nothing: %+v, %v", jobs, err)
	}
}

func TestThreatsPlansAnUnparseableURLRatherThanDroppingIt(t *testing.T) {
	// Silently planning nothing for a malformed host would report a clean component. The scanner
	// rejects it with a message naming the URL, which is a bug report rather than a false pass.
	jobs, err := NewThreats().Plan(saga.Model{}, &saga.Component{
		Hosts: []saga.Host{{Name: "broken", URL: "://nonsense"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Errorf("a malformed host was dropped at planning time: %+v", jobs)
	}
}

func TestThreatsAggregate(t *testing.T) {
	res, err := NewThreats().Aggregate([]sarif.Report{{
		Tool: "urlhaus",
		Results: []sarif.Result{
			{RuleID: "urlhaus/malware-host", Level: sarif.LevelError},
			{RuleID: "urlhaus/blacklisted", Level: sarif.LevelWarning},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "threats" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 {
		t.Errorf("summary = %+v", res.Summary)
	}
	if empty, err := NewThreats().Aggregate(nil); err != nil || empty.Summary.Errors != 0 {
		t.Errorf("empty aggregate = %+v, %v", empty, err)
	}
}
