package controllers

import (
	"slices"
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

// Selecting the Job must not replace the section-5 scanner: the Job does not run policies, so a
// component that enabled it and got only the Job would report a pass on half a benchmark. The
// default scanner keeps running alongside it, which is what makes the whole benchmark reachable
// from one component.
func TestPlanKeepsThePoliciesScannerWhenTheJobIsEnabled(t *testing.T) {
	t.Parallel()

	comp := k8sComponent(saga.ControllerSettings{"kubeBenchJob": map[string]any{"enabled": true}})
	jobs, err := Infrastructure{}.Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	// Two clusters on the component, two scanners each.
	if len(jobs) != 4 {
		t.Fatalf("got %d jobs, want 4 (2 clusters x 2 scanners)", len(jobs))
	}
	byScanner := map[string]int{}
	for _, j := range jobs {
		byScanner[j.Scanner]++
	}
	for _, want := range []string{"kube-bench-job", "kube-bench"} {
		if byScanner[want] != 2 {
			t.Errorf("scanner %q planned %d times, want 2", want, byScanner[want])
		}
	}
}

// Scanner blocks are keyed by a camelCase descriptor key, not by the scanner's own name — the
// two differ for every hyphenated scanner. Getting this wrong is silent: the block matches
// nothing and the scanner simply does not run.
func TestInfrastructureScannerSelection(t *testing.T) {
	t.Parallel()

	block := func(enabled bool) map[string]any { return map[string]any{"enabled": enabled} }

	for _, tc := range []struct {
		name     string
		settings saga.ControllerSettings
		want     []string
	}{
		{"default reads the policies section", nil, []string{"kube-bench"}},
		{"job runs alongside the default", saga.ControllerSettings{"kubeBenchJob": block(true)}, []string{"kube-bench", "kube-bench-job"}},
		{"native reader opted in", saga.ControllerSettings{"k8sPolicies": block(true)}, []string{"kube-bench", "k8s-policies"}},

		// The question this design had to answer: the node sections without section 5.
		{"node sections only", saga.ControllerSettings{
			"kubeBench":    block(false),
			"kubeBenchJob": block(true),
		}, []string{"kube-bench-job"}},

		// Native section 5 plus the node sections, which is the fast whole benchmark.
		{"native policies plus the job", saga.ControllerSettings{
			"kubeBench":    block(false),
			"kubeBenchJob": block(true),
			"k8sPolicies":  block(true),
		}, []string{"k8s-policies", "kube-bench-job"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			jobs, err := Infrastructure{}.Plan(saga.Model{}, k8sComponent(tc.settings))
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, j := range jobs {
				got[j.Scanner] = true
			}
			if len(got) != len(tc.want) {
				t.Fatalf("planned %v, want exactly %v", keysOf(got), tc.want)
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("scanner %q was not planned; got %v", w, keysOf(got))
				}
			}
		})
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
