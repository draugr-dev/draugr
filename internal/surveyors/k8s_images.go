// Package surveyors holds Draugr's built-in surveyors ("the Ravens").
package surveyors

import (
	"context"
	"fmt"

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
	return saga.Fragment{Components: []saga.Component{{Name: name, Images: images}}}, nil
}

// collectImages returns the unique images across all containers (init + regular) of the
// given pods, in first-seen order.
func collectImages(pods []corev1.Pod) []saga.Image {
	seen := make(map[string]bool)
	var images []saga.Image
	add := func(ref string) {
		if ref == "" || seen[ref] {
			return
		}
		seen[ref] = true
		images = append(images, saga.Image{Image: ref})
	}
	for _, pod := range pods {
		for _, c := range pod.Spec.InitContainers {
			add(c.Image)
		}
		for _, c := range pod.Spec.Containers {
			add(c.Image)
		}
	}
	return images
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
