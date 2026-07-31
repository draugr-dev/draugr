package surveyors

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// K8sCluster discovers the cluster itself, as something to audit rather than something to run
// workloads on.
//
// Separate from [K8sImages] rather than folded into it, though both read the same cluster through
// the same credentials. A surveyor named for images that also emitted an infrastructure component
// would surprise anyone reading `survey k8s images` in a script, and a generated descriptor is
// only worth trusting if the command that produced it predicts its contents.
//
// They also produce genuinely different things. The images are the application; the cluster is
// what it runs on. Those differ in criticality often enough that forcing them into one component
// would mean asserting a single classification over both.
type K8sCluster struct {
	// clientset builds a Kubernetes client for a survey scope; injectable for testing.
	clientset func(scope plugin.SurveyScope) (kubernetes.Interface, error)
	// currentContext names the kubeconfig context in use; injectable for testing.
	currentContext func() string
}

// NewK8sCluster returns the k8s-cluster surveyor using the ambient kubeconfig.
func NewK8sCluster() *K8sCluster {
	return &K8sCluster{clientset: defaultClientset, currentContext: currentKubeContext}
}

// Info identifies the surveyor.
func (K8sCluster) Info() plugin.SurveyorInfo {
	return plugin.SurveyorInfo{
		Name:     "k8s-cluster",
		Provides: []plugin.TargetKind{plugin.TargetInfra},
	}
}

// Survey returns the cluster as an infrastructure component.
//
// The cluster is reached before it is described. Emitting a component for a cluster that cannot
// be contacted would write a descriptor whose first scan fails, and the descriptor is the thing
// people trust afterwards — better to fail here, where the operator is watching, than at the
// scan of a cluster they believed had been checked.
// The context is unused: the reachability probe is client-go's discovery ServerVersion, which
// predates context and takes none. The context-aware alternative goes through the discovery
// REST client, which is nil on the fake clientset and so cannot be tested — a probe that only
// runs against a real cluster is a probe nothing checks.
func (k K8sCluster) Survey(_ context.Context, scope plugin.SurveyScope) (saga.Fragment, error) {
	cs, err := k.clientset(scope)
	if err != nil {
		return saga.Fragment{}, fmt.Errorf("k8s-cluster: %w", err)
	}
	if _, err := cs.Discovery().ServerVersion(); err != nil {
		return saga.Fragment{}, fmt.Errorf("k8s-cluster: reach the cluster: %w", err)
	}

	ref := scopeContext(scope)
	if ref == "" {
		ref = k.currentContext()
	}

	comp := saga.Component{
		Name: componentNameFor(ref),
		Infrastructure: []saga.Infrastructure{{
			Kind: "kubernetes",
			Ref:  ref,
		}},
	}
	// A survey scoped to a namespace describes a component that owns that namespace, not the
	// whole cluster. Writing it here is what makes the descriptor match the survey that produced
	// it; leaving it out would emit a cluster-wide component the operator then has to narrow by
	// hand, having already said which namespace they meant.
	if scope.Ref != "" {
		comp.Infrastructure[0].Namespaces = []string{scope.Ref}
	}

	// exposure and criticality are deliberately absent. Neither is a property of the cluster —
	// they are judgements about what its failure costs, which `draugr classify` asks a human.
	return saga.Fragment{Components: []saga.Component{comp}}, nil
}

// componentNameFor names the component after the cluster it describes.
//
// A descriptor with a component called "cluster" says nothing once there are two of them, and the
// context is what the operator already calls it — the same string the infrastructure scanner
// resolves back to a kubeconfig entry.
func componentNameFor(ref string) string {
	if ref == "" {
		return "cluster"
	}
	return ref
}

// scopeContext reads the kubeconfig context a survey was pointed at, if any.
const scopeContextKey = "context"

func scopeContext(scope plugin.SurveyScope) string {
	if scope.Config == nil {
		return ""
	}
	v, _ := scope.Config[scopeContextKey].(string)
	return v
}

// currentKubeContext reports the kubeconfig's current context, or "" if it cannot be read.
func currentKubeContext() string {
	raw, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		return ""
	}
	return raw.CurrentContext
}
