package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestTLSInfo(t *testing.T) {
	info := NewTLS().Info()
	if info.Name != "tls" {
		t.Errorf("name = %q", info.Name)
	}
	if info.Scope != plugin.ScopeComponent {
		t.Errorf("scope = %v, want component", info.Scope)
	}
	if len(info.DefaultScanners) != 1 || info.DefaultScanners[0] != tlsProbeScanner {
		t.Errorf("default scanners = %v", info.DefaultScanners)
	}
}

func TestTLSPlanOneJobPerHost(t *testing.T) {
	comp := &saga.Component{Name: "web", Hosts: []saga.Host{
		{Name: "api", URL: "https://api.example.test"},
		{Name: "site", URL: "https://example.test"},
		{Name: "no-url"}, // skipped
	}}
	jobs, err := NewTLS().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs (url-less host skipped), got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != tlsProbeScanner {
			t.Errorf("scanner = %q", j.Scanner)
		}
		if _, ok := j.Target.(plugin.HostTarget); !ok {
			t.Errorf("target = %T, want HostTarget", j.Target)
		}
	}
}

func TestTLSPlanNilComponent(t *testing.T) {
	jobs, err := NewTLS().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component: got (%v,%v), want (nil,nil)", jobs, err)
	}
}

// The control honors per-scanner selection/config like the other controls.
func TestTLSPlanRespectsScannerConfig(t *testing.T) {
	comp := &saga.Component{
		Name:  "web",
		Hosts: []saga.Host{{Name: "api", URL: "https://api.example.test"}},
		Controllers: map[string]saga.ControllerSettings{
			"tls": {configKeyFor(tlsProbeScanner): map[string]any{"enabled": false}},
		},
	}
	jobs, err := NewTLS().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("disabling the default scanner should plan no jobs, got %d", len(jobs))
	}
}

func TestTLSAggregate(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "tlsProbe", Results: []sarif.Result{
			{RuleID: "tls-cert-expired", Level: sarif.LevelError},
			{RuleID: "tls-cert-expiring", Level: sarif.LevelWarning},
			{RuleID: "tls-no-tls13", Level: sarif.LevelNote},
		}},
	}
	res, err := NewTLS().Aggregate(reports)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if res.Control != "tls" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 || res.Summary.Notes != 1 {
		t.Errorf("summary = %+v", res.Summary)
	}
}

func TestTLSAggregateEmpty(t *testing.T) {
	res, err := NewTLS().Aggregate(nil)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if res.Summary.Errors != 0 || len(res.Report.Results) != 0 {
		t.Errorf("empty aggregate = %+v", res)
	}
}
