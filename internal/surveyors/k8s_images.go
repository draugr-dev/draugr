// Package surveyors holds Draugr's built-in surveyors.
package surveyors

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// K8sImages discovers the unique container images running in a Kubernetes cluster or
// namespace and returns them as a Saga component.
type K8sImages struct {
	// clientset builds a Kubernetes client for a survey scope; injectable for testing.
	clientset func(scope plugin.SurveyScope) (kubernetes.Interface, error)
}

// NewK8sImages returns the k8s-images surveyor using the ambient kubeconfig.
func NewK8sImages() *K8sImages {
	return &K8sImages{clientset: defaultClientset}
}

// Info identifies the surveyor.
func (K8sImages) Info() plugin.SurveyorInfo {
	return plugin.SurveyorInfo{
		Name:     "k8s-images",
		Provides: []plugin.TargetKind{plugin.TargetImage},
	}
}

// Survey lists pods in the scope's namespace (Ref; empty means every namespace) and returns one
// component per namespace, whose images are the unique container images running in it.
//
// A namespace is the unit, whether or not one was named. Collapsing a whole cluster into a single
// component loses the two things that make the result usable: a namespace is what a team owns, so
// it is what a finding has to be attributed to, and exposure is a property of a namespace's
// topology — one Ingress anywhere would otherwise mark every image in the cluster as public.
// `--namespace a,b` already produces a component each; no namespace means all of them, not one of
// them.
func (k K8sImages) Survey(ctx context.Context, scope plugin.SurveyScope) (saga.Fragment, error) {
	cs, err := k.clientset(scope)
	if err != nil {
		return saga.Fragment{}, fmt.Errorf("k8s-images: %w", err)
	}

	namespace := scope.Ref
	if err := requireNamespace(ctx, cs, namespace); err != nil {
		return saga.Fragment{}, fmt.Errorf("k8s-images: %w", err)
	}
	pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return saga.Fragment{}, fmt.Errorf("k8s-images: list pods: %w", err)
	}

	byNamespace := imagesByNamespace(pods.Items)
	if len(byNamespace) == 0 {
		// The scope exists and is running nothing, which is a real answer rather than a failure —
		// but silence here reads as "surveyed and found your images", and the descriptor that
		// results scans nothing.
		if namespace != "" {
			slog.Warn("no running images: this namespace contributes no component",
				"namespace", namespace)
		}
		return saga.Fragment{}, nil
	}

	names := make([]string, 0, len(byNamespace))
	for ns := range byNamespace {
		names = append(names, ns)
	}
	// Sorted so the descriptor a survey writes does not reorder itself between runs, which would
	// turn every re-survey into a diff nobody can read.
	sort.Strings(names)

	// Proposed exposures for every namespace at once. Three list calls over the scope rather than
	// three per namespace: on a cluster with eighty of them the per-namespace form is two hundred
	// and forty round trips, and the answer is identical.
	exposures := inferExposures(ctx, cs, namespace, names)

	comps := make([]saga.Component, 0, len(names))
	for _, ns := range names {
		comp := saga.Component{Name: ns, Images: byNamespace[ns]}
		// A suggestion for a human to confirm or adjust, not a measurement.
		if exp, ok := exposures[ns]; ok {
			comp.Exposure = exp
		}
		comps = append(comps, comp)
	}
	return saga.Fragment{Components: comps}, nil
}

// inferExposures proposes an exposure for each namespace, from the Kubernetes topology it can
// read: an Ingress or an externally-reachable Service (LoadBalancer/NodePort) implies internet
// reach; otherwise a NetworkPolicy implies restricted; otherwise internal.
//
// One pass over the whole scope rather than one per namespace. The three lists it needs can each
// be answered cluster-wide in a single call, and a survey of a large cluster is the case that has
// to stay usable — asking per namespace turns eighty of them into two hundred and forty round
// trips for the same answer.
//
// Best-effort: a resource type it cannot list is skipped, and if none can be listed it proposes
// nothing at all rather than calling everything internal on no evidence. Authentication cannot be
// inferred reliably, so internet-reachable is proposed as "public"; a human downgrades to
// "authenticated" if it sits behind auth.
func inferExposures(ctx context.Context, cs kubernetes.Interface, scope string, namespaces []string) map[string]saga.Exposure {
	public := map[string]bool{}
	restricted := map[string]bool{}
	queried := false

	if ing, err := cs.NetworkingV1().Ingresses(scope).List(ctx, metav1.ListOptions{}); err == nil {
		queried = true
		for _, i := range ing.Items {
			public[i.Namespace] = true
		}
	} else {
		slog.Warn("infer exposure: list ingresses", "scope", scopeLabel(scope), "error", err)
	}

	if svcs, err := cs.CoreV1().Services(scope).List(ctx, metav1.ListOptions{}); err == nil {
		queried = true
		for _, s := range svcs.Items {
			if s.Spec.Type == corev1.ServiceTypeLoadBalancer || s.Spec.Type == corev1.ServiceTypeNodePort {
				public[s.Namespace] = true
			}
		}
	} else {
		slog.Warn("infer exposure: list services", "scope", scopeLabel(scope), "error", err)
	}

	if nps, err := cs.NetworkingV1().NetworkPolicies(scope).List(ctx, metav1.ListOptions{}); err == nil {
		queried = true
		for _, n := range nps.Items {
			restricted[n.Namespace] = true
		}
	} else {
		slog.Warn("infer exposure: list network policies", "scope", scopeLabel(scope), "error", err)
	}

	if !queried {
		return nil // could not read any topology — propose nothing
	}

	out := make(map[string]saga.Exposure, len(namespaces))
	for _, ns := range namespaces {
		switch {
		case public[ns]:
			out[ns] = saga.ExposurePublic
		case restricted[ns]:
			out[ns] = saga.ExposureRestricted
		default:
			out[ns] = saga.ExposureInternal
		}
	}
	return out
}

// scopeLabel names what a failed lookup covered, so a warning about the whole cluster does not
// read as one about a namespace called "".
func scopeLabel(scope string) string {
	if scope == "" {
		return "all namespaces"
	}
	return scope
}

// imagesByNamespace groups the unique images across all containers (init + regular) of the given
// pods by the namespace they run in, each in first-seen order.
//
// Uniqueness is per namespace, not per cluster: the same image running in two namespaces is two
// components' problem, and deduplicating across them would leave one of the two describing a
// surface it has. The engine still scans it once — identical targets collapse there — so the
// honest descriptor costs nothing.
//
// Each image carries the immutable digest of what is actually running (from the container's
// status), captured so result caching is content-addressed — a rebuilt image under the same tag
// re-scans.
func imagesByNamespace(pods []corev1.Pod) map[string][]saga.Image {
	out := map[string][]saga.Image{}
	seen := map[string]map[string]bool{}
	for _, pod := range pods {
		ns := pod.Namespace
		if seen[ns] == nil {
			seen[ns] = map[string]bool{}
		}
		digests := runningDigests(pod)
		add := func(ref, digest string) {
			if ref == "" || seen[ns][ref] {
				return
			}
			seen[ns][ref] = true
			out[ns] = append(out[ns], saga.Image{Image: ref, Digest: digest})
		}
		for _, c := range pod.Spec.InitContainers {
			add(c.Image, digests[c.Name])
		}
		for _, c := range pod.Spec.Containers {
			add(c.Image, digests[c.Name])
		}
	}
	return out
}

// runningDigests maps a pod's container names to the content digest of the image each is
// actually running, read from the container statuses (init + regular). Containers not yet
// running, or whose runtime reports no digest, are simply absent from the map.
func runningDigests(pod corev1.Pod) map[string]string {
	digests := make(map[string]string)
	record := func(statuses []corev1.ContainerStatus) {
		for _, s := range statuses {
			if d := digestFromImageID(s.ImageID); d != "" {
				digests[s.Name] = d
			}
		}
	}
	record(pod.Status.InitContainerStatuses)
	record(pod.Status.ContainerStatuses)
	return digests
}

// digestFromImageID extracts the bare "algorithm:hex" digest from a Kubernetes
// ContainerStatus.ImageID, whose form varies by runtime — e.g.
// "docker-pullable://repo@sha256:…", "repo@sha256:…", or a bare "sha256:…". Returns ""
// when no digest is present (e.g. an image pulled purely by tag on some runtimes).
func digestFromImageID(imageID string) string {
	if i := strings.LastIndex(imageID, "@"); i >= 0 {
		return imageID[i+1:]
	}
	if strings.HasPrefix(imageID, "sha256:") || strings.HasPrefix(imageID, "sha512:") {
		return imageID
	}
	return ""
}

// defaultClientset builds a Kubernetes client from the ambient kubeconfig (KUBECONFIG /
// ~/.kube/config / in-cluster).
// defaultClientset builds a client for the scope's kubeconfig context, or the ambient one.
//
// The override is what makes `--context` mean something. Reading the flag and then connecting to
// whatever the machine happens to have selected would survey one cluster while the operator
// named another — and write a descriptor labelled with the name they gave.
func defaultClientset(scope plugin.SurveyScope) (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{CurrentContext: scopeContext(scope)}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
