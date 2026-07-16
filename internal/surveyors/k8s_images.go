// Package surveyors holds Draugr's built-in surveyors ("the Ravens").
package surveyors

import (
	"context"
	"fmt"
	"log/slog"
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

// Survey lists pods in the scope's namespace (Ref; empty means all namespaces) and
// returns a component whose images are the unique container images found.
func (k K8sImages) Survey(ctx context.Context, scope plugin.SurveyScope) (saga.Fragment, error) {
	cs, err := k.clientset(scope)
	if err != nil {
		return saga.Fragment{}, fmt.Errorf("k8s-images: %w", err)
	}

	namespace := scope.Ref
	pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return saga.Fragment{}, fmt.Errorf("k8s-images: list pods: %w", err)
	}

	images := collectImages(pods.Items)
	if len(images) == 0 {
		return saga.Fragment{}, nil
	}

	name := namespace
	if name == "" {
		name = "cluster"
	}
	comp := saga.Component{Name: name, Images: images}
	// Propose an exposure from the namespace's topology (a specific namespace only — a
	// whole-cluster survey lumps many namespaces into one component, where exposure is
	// meaningless). The value is a suggestion for a human to confirm/adjust.
	if namespace != "" {
		if exp, ok := inferExposure(ctx, cs, namespace); ok {
			comp.Exposure = exp
		}
	}
	return saga.Fragment{Components: []saga.Component{comp}}, nil
}

// inferExposure proposes a component's exposure from a namespace's Kubernetes topology:
// an Ingress or an externally-reachable Service (LoadBalancer/NodePort) implies internet
// reach; otherwise a NetworkPolicy implies restricted; otherwise internal. It is best-effort
// — a resource type it can't list is skipped, and if none can be listed it proposes nothing
// (ok=false). Authentication can't be inferred reliably, so internet-reachable is proposed as
// "public"; a human downgrades to "authenticated" if it sits behind auth.
func inferExposure(ctx context.Context, cs kubernetes.Interface, namespace string) (saga.Exposure, bool) {
	queried := false

	if ing, err := cs.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{}); err == nil {
		queried = true
		if len(ing.Items) > 0 {
			return saga.ExposurePublic, true
		}
	} else {
		slog.Warn("infer exposure: list ingresses", "namespace", namespace, "error", err)
	}

	if svcs, err := cs.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{}); err == nil {
		queried = true
		for _, s := range svcs.Items {
			if s.Spec.Type == corev1.ServiceTypeLoadBalancer || s.Spec.Type == corev1.ServiceTypeNodePort {
				return saga.ExposurePublic, true
			}
		}
	} else {
		slog.Warn("infer exposure: list services", "namespace", namespace, "error", err)
	}

	if nps, err := cs.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{}); err == nil {
		queried = true
		if len(nps.Items) > 0 {
			return saga.ExposureRestricted, true
		}
	} else {
		slog.Warn("infer exposure: list network policies", "namespace", namespace, "error", err)
	}

	if !queried {
		return "", false // couldn't read any topology — propose nothing
	}
	return saga.ExposureInternal, true
}

// collectImages returns the unique images across all containers (init + regular) of the
// given pods, in first-seen order. Each image carries the immutable digest of what is
// actually running (from the container's status), captured so result caching is
// content-addressed — a rebuilt image under the same tag re-scans.
func collectImages(pods []corev1.Pod) []saga.Image {
	seen := make(map[string]bool)
	var images []saga.Image
	add := func(ref, digest string) {
		if ref == "" || seen[ref] {
			return
		}
		seen[ref] = true
		images = append(images, saga.Image{Image: ref, Digest: digest})
	}
	for _, pod := range pods {
		digests := runningDigests(pod)
		for _, c := range pod.Spec.InitContainers {
			add(c.Image, digests[c.Name])
		}
		for _, c := range pod.Spec.Containers {
			add(c.Image, digests[c.Name])
		}
	}
	return images
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
func defaultClientset(_ plugin.SurveyScope) (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
