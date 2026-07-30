package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func k8sComponent(settings saga.ControllerSettings) *saga.Component {
	c := &saga.Component{
		Name: "platform",
		Infrastructure: []saga.Infrastructure{
			{Kind: "kubernetes", Ref: "prod"},
			{Kind: "kubernetes", Ref: "staging"},
		},
	}
	if settings != nil {
		c.Controllers = map[string]saga.ControllerSettings{"infrastructure": settings}
	}
	return c
}

func TestInfrastructureInfo(t *testing.T) {
	info := NewInfrastructure().Info()
	if info.Name != "infrastructure" {
		t.Errorf("name = %q", info.Name)
	}
	// Component-scoped because `infrastructure:` is a component field in the Saga — what this
	// component runs on.
	if info.Scope != plugin.ScopeComponent {
		t.Errorf("scope = %q, want component", info.Scope)
	}
	if len(info.DefaultScanners) != 1 || info.DefaultScanners[0] != "kube-bench" {
		t.Errorf("default scanners = %v", info.DefaultScanners)
	}
}

func TestInfrastructurePlanOneJobPerCluster(t *testing.T) {
	jobs, err := Infrastructure{}.Plan(saga.Model{}, k8sComponent(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for i, want := range []string{"kubernetes/prod", "kubernetes/staging"} {
		if jobs[i].Scanner != "kube-bench" {
			t.Errorf("job %d scanner = %q", i, jobs[i].Scanner)
		}
		if got := jobs[i].Target.Identity(); got != want {
			t.Errorf("job %d target = %q, want %q", i, got, want)
		}
	}
}

// A descriptor may name surfaces Draugr has no benchmark for. Skipping them beats refusing to
// plan the ones it does understand — otherwise describing your estate honestly costs you scans.
func TestInfrastructurePlanSkipsOtherPlatforms(t *testing.T) {
	comp := &saga.Component{Infrastructure: []saga.Infrastructure{
		{Kind: "aws", Ref: "prod-account"},
		{Kind: "Kubernetes", Ref: "prod"}, // case-insensitive
	}}
	jobs, err := Infrastructure{}.Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Target.Identity() != "kubernetes/prod" {
		t.Errorf("want only the kubernetes surface, got %+v", jobs)
	}
}

func TestInfrastructurePlanNilComponent(t *testing.T) {
	jobs, err := Infrastructure{}.Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Errorf("nil component should plan nothing, got %v, %v", jobs, err)
	}
}

// Settings reach the scanner untouched. The control has no opinion about which CIS sections to
// run beyond the default; it is the scanner that knows which of them travel.
func TestInfrastructurePassesSettingsThrough(t *testing.T) {
	jobs, err := Infrastructure{}.Plan(saga.Model{}, k8sComponent(saga.ControllerSettings{
		"benchmark": "cis-1.9",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := jobs[0].Config["benchmark"]; got != "cis-1.9" {
		t.Errorf("benchmark = %v, want cis-1.9", got)
	}
}

// Project settings should apply to every component without being restated, and a component
// should still be able to say something different.
func TestInfrastructureMergesProjectAndComponentSettings(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"infrastructure": {"benchmark": "cis-1.9"},
	}}}
	jobs, err := Infrastructure{}.Plan(model, k8sComponent(saga.ControllerSettings{"targets": "policies"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := jobs[0].Config["benchmark"]; got != "cis-1.9" {
		t.Errorf("project setting did not reach the job: %v", jobs[0].Config)
	}
	if got := jobs[0].Config["targets"]; got != "policies" {
		t.Errorf("component setting did not reach the job: %v", jobs[0].Config)
	}
}

func TestInfrastructureAggregate(t *testing.T) {
	res, err := Infrastructure{}.Aggregate([]sarif.Report{{Results: []sarif.Result{
		{RuleID: "cis/5.1.1", Level: sarif.LevelError},
		{RuleID: "cis/5.2.1", Level: sarif.LevelWarning},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "infrastructure" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 {
		t.Errorf("summary = %+v", res.Summary)
	}
}

func TestInfrastructureAggregateEmpty(t *testing.T) {
	res, err := Infrastructure{}.Aggregate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Errors != 0 || res.Summary.Warnings != 0 {
		t.Errorf("empty aggregate should be clean, got %+v", res.Summary)
	}
}
