package surveyors

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func clusterSurveyor(cs kubernetes.Interface, ctxName string) K8sCluster {
	return K8sCluster{
		clientset:      func(plugin.SurveyScope) (kubernetes.Interface, error) { return cs, nil },
		currentContext: func() string { return ctxName },
	}
}

func TestK8sClusterInfo(t *testing.T) {
	t.Parallel()
	info := NewK8sCluster().Info()
	if info.Name != "k8s-cluster" {
		t.Errorf("name = %q", info.Name)
	}
	// Infrastructure, not images — the whole reason this is a separate surveyor.
	if len(info.Provides) != 1 || info.Provides[0] != plugin.TargetInfra {
		t.Errorf("provides = %v, want [infrastructure]", info.Provides)
	}
}

func TestK8sClusterEmitsAnInfrastructureComponent(t *testing.T) {
	t.Parallel()

	frag, err := clusterSurveyor(fake.NewSimpleClientset(), "prod-cluster").
		Survey(context.Background(), plugin.SurveyScope{})
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.Components) != 1 {
		t.Fatalf("want one component, got %d", len(frag.Components))
	}
	c := frag.Components[0]
	// Named for the context: "cluster" says nothing once a descriptor has two of them.
	if c.Name != "prod-cluster" {
		t.Errorf("name = %q, want the context name", c.Name)
	}
	if len(c.Infrastructure) != 1 || c.Infrastructure[0].Kind != "kubernetes" || c.Infrastructure[0].Ref != "prod-cluster" {
		t.Errorf("infrastructure = %+v", c.Infrastructure)
	}
	if len(c.Images) != 0 || len(c.Repositories) != 0 {
		t.Error("this surveyor describes the cluster, not what runs on it")
	}
	// Judgements a cluster does not hold. Guessing them would put a number on risk that nobody
	// decided.
	if c.Exposure != "" || c.Criticality != "" {
		t.Errorf("exposure/criticality should be left for `draugr classify`, got %q/%q", c.Exposure, c.Criticality)
	}
}

// A namespace-scoped survey describes a component that owns that namespace. Emitting a
// cluster-wide one would make the operator narrow by hand what they already said.
func TestK8sClusterWritesTheScopedNamespace(t *testing.T) {
	t.Parallel()

	frag, err := clusterSurveyor(fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}), "prod").
		Survey(context.Background(), plugin.SurveyScope{Ref: "team-a"})
	if err != nil {
		t.Fatal(err)
	}
	got := frag.Components[0].Infrastructure[0].Namespaces
	if len(got) != 1 || got[0] != "team-a" {
		t.Errorf("namespaces = %v, want [team-a]", got)
	}

	unscoped, err := clusterSurveyor(fake.NewSimpleClientset(), "prod").
		Survey(context.Background(), plugin.SurveyScope{})
	if err != nil {
		t.Fatal(err)
	}
	if ns := unscoped.Components[0].Infrastructure[0].Namespaces; len(ns) != 0 {
		t.Errorf("an unscoped survey owns the whole cluster, got namespaces %v", ns)
	}
}

// --context names the cluster in the descriptor, and must be the cluster that was contacted.
func TestK8sClusterPrefersTheRequestedContext(t *testing.T) {
	t.Parallel()

	frag, err := clusterSurveyor(fake.NewSimpleClientset(), "whatever-the-machine-selected").
		Survey(context.Background(), plugin.SurveyScope{Config: plugin.Config{"context": "staging"}})
	if err != nil {
		t.Fatal(err)
	}
	if ref := frag.Components[0].Infrastructure[0].Ref; ref != "staging" {
		t.Errorf("ref = %q, want the requested context", ref)
	}
}

// A component for a cluster nobody can reach is a descriptor whose first scan fails — and the
// descriptor is what people trust afterwards.
func TestK8sClusterFailsWhenTheClusterIsUnreachable(t *testing.T) {
	t.Parallel()

	s := K8sCluster{
		clientset:      func(plugin.SurveyScope) (kubernetes.Interface, error) { return nil, errors.New("no kubeconfig") },
		currentContext: func() string { return "" },
	}
	if _, err := s.Survey(context.Background(), plugin.SurveyScope{}); err == nil {
		t.Fatal("want an error rather than a component for a cluster that was never contacted")
	}
}

func TestComponentNameFallsBackWhenNoContextIsKnown(t *testing.T) {
	t.Parallel()
	if got := componentNameFor(""); got != "cluster" {
		t.Errorf("componentNameFor(\"\") = %q", got)
	}
}
