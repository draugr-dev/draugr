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
		Kubernetes: []saga.ClusterRef{
			{Cluster: "prod"},
			{Cluster: "staging"},
		},
	}
	if settings != nil {
		c.Controls = map[string]saga.ControllerSettings{"kubernetes": settings}
	}
	return c
}

func TestKubernetesInfo(t *testing.T) {
	info := NewKubernetes().Info()
	if info.Name != "kubernetes" {
		t.Errorf("name = %q", info.Name)
	}
	// Component-scoped because `kubernetes:` is a component field in the Saga: the clusters this
	// component runs on.
	if info.Scope != plugin.ScopeComponent {
		t.Errorf("scope = %q, want component", info.Scope)
	}
	// The native reader, not the exec'd one: both decide the same 11 checks, so defaulting to
	// the one that needs no kubectl and creates nothing costs no coverage.
	if len(info.DefaultScanners) != 1 || info.DefaultScanners[0] != "draugr-k8s-policies" {
		t.Errorf("default scanners = %v, want [draugr-k8s-policies]", info.DefaultScanners)
	}
}

func TestKubernetesPlanOneJobPerCluster(t *testing.T) {
	jobs, err := Kubernetes{}.Plan(saga.Model{}, k8sComponent(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for i, want := range []string{"kubernetes/prod", "kubernetes/staging"} {
		if jobs[i].Scanner != "draugr-k8s-policies" {
			t.Errorf("job %d scanner = %q", i, jobs[i].Scanner)
		}
		if got := jobs[i].Target.Identity(); got != want {
			t.Errorf("job %d target = %q, want %q", i, got, want)
		}
	}
}

func TestKubernetesPlanNilComponent(t *testing.T) {
	jobs, err := Kubernetes{}.Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Errorf("nil component should plan nothing, got %v, %v", jobs, err)
	}
}

// Settings reach the scanner untouched. The control has no opinion about which CIS sections to
// run beyond the default; it is the scanner that knows which of them travel.
func TestKubernetesPassesSettingsThrough(t *testing.T) {
	jobs, err := Kubernetes{}.Plan(saga.Model{}, k8sComponent(saga.ControllerSettings{
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
func TestKubernetesMergesProjectAndComponentSettings(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"kubernetes": {"benchmark": "cis-1.9"},
	}}}
	jobs, err := Kubernetes{}.Plan(model, k8sComponent(saga.ControllerSettings{"targets": "policies"}))
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

func TestKubernetesAggregate(t *testing.T) {
	res, err := Kubernetes{}.Aggregate([]sarif.Report{{Results: []sarif.Result{
		{RuleID: "cis/5.1.1", Level: sarif.LevelError},
		{RuleID: "cis/5.2.1", Level: sarif.LevelWarning},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "kubernetes" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 {
		t.Errorf("summary = %+v", res.Summary)
	}
}

func TestKubernetesAggregateEmpty(t *testing.T) {
	res, err := Kubernetes{}.Aggregate(nil)
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
	jobs, err := Kubernetes{}.Plan(saga.Model{}, comp)
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
	for _, want := range []string{"kube-bench-job", "draugr-k8s-policies"} {
		if byScanner[want] != 2 {
			t.Errorf("scanner %q planned %d times, want 2", want, byScanner[want])
		}
	}
}

// Scanner blocks are keyed by a camelCase descriptor key, not by the scanner's own name, the two
// differ for every hyphenated scanner. Getting this wrong is silent: the block matches nothing
// and the scanner simply does not run.
func TestKubernetesScannerSelection(t *testing.T) {
	t.Parallel()

	block := func(enabled bool) map[string]any { return map[string]any{"enabled": enabled} }

	for _, tc := range []struct {
		name     string
		settings saga.ControllerSettings
		want     []string
	}{
		{"default reads the policies section natively", nil, []string{"draugr-k8s-policies"}},
		{"job runs alongside the default", saga.ControllerSettings{"kubeBenchJob": block(true)}, []string{"draugr-k8s-policies", "kube-bench-job"}},
		{"exec'd reader opted in alongside the default", saga.ControllerSettings{"kubeBench": block(true)}, []string{"draugr-k8s-policies", "kube-bench"}},

		// The question this design had to answer: the node sections without section 5.
		{"node sections only", saga.ControllerSettings{
			"draugrK8sPolicies": block(false),
			"kubeBenchJob":      block(true),
		}, []string{"kube-bench-job"}},

		// Native section 5 plus the node sections, which is the fast whole benchmark.
		// The exec'd reader in place of the native one, for anyone who wants kube-bench itself
		// to be the thing that ran.
		{"exec'd policies plus the job", saga.ControllerSettings{
			"draugrK8sPolicies": block(false),
			"kubeBench":         block(true),
			"kubeBenchJob":      block(true),
		}, []string{"kube-bench", "kube-bench-job"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			jobs, err := Kubernetes{}.Plan(saga.Model{}, k8sComponent(tc.settings))
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

// The control's own `enabled` flag, and the scanner blocks beneath it, are not a scanner's
// options. Copying them into a scanner's config hands it keys that are not its own, and a
// scanner that declares what it accepts then refuses the whole job, naming a key the descriptor
// never wrote at that level.
//
// Enabling a control is the most ordinary thing a descriptor does, and `draugr survey` writes it
// that way. So this is reachable from a generated descriptor, not only a hand-written one.
func TestKubernetesDoesNotPassTheControlsOwnKeysToAScanner(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"kubernetes": {
			"enabled":           true,
			"context":           "prod",
			"draugrK8sPolicies": saga.ControllerSettings{"enabled": true},
			"kubeBench":         saga.ControllerSettings{"enabled": false},
		},
	}}}
	comp := &saga.Component{
		Name:       "cluster",
		Kubernetes: []saga.ClusterRef{{Cluster: "prod"}},
	}
	jobs, err := Kubernetes{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) == 0 {
		t.Fatal("no jobs planned")
	}
	for _, j := range jobs {
		if _, leaked := j.Config["enabled"]; leaked {
			t.Errorf("%s got the control's own enabled flag as an option", j.Scanner)
		}
		for _, k := range []string{"draugrK8sPolicies", "kubeBench"} {
			if _, leaked := j.Config[k]; leaked {
				t.Errorf("%s got another scanner's block as an option", j.Scanner)
			}
		}
		// The genuine control-level setting still reaches every scanner that needs it.
		if j.Config["context"] != "prod" {
			t.Errorf("%s lost the shared context: %v", j.Scanner, j.Config)
		}
	}
}

// Each entry's cluster is looked up in clusters:, and its facts reach the target: the context
// that reaches it, its benchmark and who operates it. Two clusters, so a fact cannot be shared
// between them by accident.
func TestKubernetesPlanCarriesEachClustersFacts(t *testing.T) {
	model := saga.Model{Clusters: map[string]saga.Cluster{
		"prod":    {Context: "prod-admin", Benchmark: "eks-1.5.0", OperatedBy: saga.OperatedByProvider},
		"staging": {Context: "staging-admin", Version: "1.30"},
	}}
	jobs, err := Kubernetes{}.Plan(model, k8sComponent(nil))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]plugin.KubernetesTarget{}
	for _, j := range jobs {
		k := j.Target.(plugin.KubernetesTarget)
		got[k.Cluster] = k
	}
	if p := got["prod"]; p.Context != "prod-admin" || p.Benchmark != "eks-1.5.0" || !p.ProviderOperated {
		t.Errorf("prod = %+v", p)
	}
	if s := got["staging"]; s.Context != "staging-admin" || s.Version != "1.30" || s.Benchmark != "" || s.ProviderOperated {
		t.Errorf("staging = %+v", s)
	}
}
