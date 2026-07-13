package surveyors

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func pod(ns, name string, images ...string) *corev1.Pod {
	var containers []corev1.Container
	for i, img := range images {
		containers = append(containers, corev1.Container{Name: name, Image: img})
		_ = i
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.PodSpec{Containers: containers},
	}
}

func withClient(cs kubernetes.Interface) K8sImages {
	return K8sImages{clientset: func(plugin.SurveyScope) (kubernetes.Interface, error) { return cs, nil }}
}

func TestK8sImagesInfo(t *testing.T) {
	if NewK8sImages().Info().Name != "k8s-images" {
		t.Error("wrong name")
	}
}

func TestK8sImagesSurveyDedups(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pod("prod", "a", "repo/x:1", "repo/y:1"),
		pod("prod", "b", "repo/x:1"), // duplicate image
	)
	frag, err := withClient(cs).Survey(context.Background(), plugin.SurveyScope{Ref: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(frag.Components))
	}
	c := frag.Components[0]
	if c.Name != "prod" {
		t.Errorf("component name = %q, want prod", c.Name)
	}
	if len(c.Images) != 2 {
		t.Errorf("want 2 unique images, got %d: %+v", len(c.Images), c.Images)
	}
}

func TestK8sImagesEmptyNamespaceName(t *testing.T) {
	cs := fake.NewSimpleClientset(pod("", "a", "repo/x:1"))
	frag, err := withClient(cs).Survey(context.Background(), plugin.SurveyScope{})
	if err != nil {
		t.Fatal(err)
	}
	if frag.Components[0].Name != "cluster" {
		t.Errorf("empty namespace should name component 'cluster', got %q", frag.Components[0].Name)
	}
}

func TestK8sImagesNoPods(t *testing.T) {
	frag, err := withClient(fake.NewSimpleClientset()).Survey(context.Background(), plugin.SurveyScope{Ref: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.Components) != 0 {
		t.Errorf("no pods should yield no components, got %d", len(frag.Components))
	}
}

func TestK8sImagesClientError(t *testing.T) {
	k := K8sImages{clientset: func(plugin.SurveyScope) (kubernetes.Interface, error) {
		return nil, errors.New("no kubeconfig")
	}}
	if _, err := k.Survey(context.Background(), plugin.SurveyScope{}); err == nil {
		t.Fatal("expected client error")
	}
}

func TestDefaultClientsetErrorsWithoutConfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig-xyz")
	t.Setenv("HOME", t.TempDir()) // avoid picking up a real ~/.kube/config
	if _, err := defaultClientset(plugin.SurveyScope{}); err == nil {
		t.Skip("environment has ambient kube config; error path not exercised")
	}
}

func TestCollectImagesIncludesInitContainers(t *testing.T) {
	p := &corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init", Image: "init:1"}},
		Containers:     []corev1.Container{{Name: "app", Image: "app:1"}},
	}}
	imgs := collectImages([]corev1.Pod{*p})
	if len(imgs) != 2 {
		t.Fatalf("want init + app images, got %+v", imgs)
	}
}

func TestInferExposurePublicFromIngress(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pod("prod", "a", "repo/x:1"),
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "www", Namespace: "prod"}},
	)
	frag, err := withClient(cs).Survey(context.Background(), plugin.SurveyScope{Ref: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if frag.Components[0].Exposure != saga.ExposurePublic {
		t.Errorf("ingress → exposure = %q, want public", frag.Components[0].Exposure)
	}
}

func TestInferExposurePublicFromLoadBalancer(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pod("prod", "a", "repo/x:1"),
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "prod"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
		},
	)
	frag, _ := withClient(cs).Survey(context.Background(), plugin.SurveyScope{Ref: "prod"})
	if frag.Components[0].Exposure != saga.ExposurePublic {
		t.Errorf("LoadBalancer → exposure = %q, want public", frag.Components[0].Exposure)
	}
}

func TestInferExposureRestrictedFromNetworkPolicy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pod("prod", "a", "repo/x:1"),
		&corev1.Service{ // ClusterIP (not external)
			ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "prod"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
		},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "np", Namespace: "prod"}},
	)
	frag, _ := withClient(cs).Survey(context.Background(), plugin.SurveyScope{Ref: "prod"})
	if frag.Components[0].Exposure != saga.ExposureRestricted {
		t.Errorf("network policy → exposure = %q, want restricted", frag.Components[0].Exposure)
	}
}

func TestInferExposureInternalByDefault(t *testing.T) {
	cs := fake.NewSimpleClientset(pod("prod", "a", "repo/x:1")) // no ingress/svc/netpol
	frag, _ := withClient(cs).Survey(context.Background(), plugin.SurveyScope{Ref: "prod"})
	if frag.Components[0].Exposure != saga.ExposureInternal {
		t.Errorf("no topology signal → exposure = %q, want internal", frag.Components[0].Exposure)
	}
}

func TestNoExposureForWholeCluster(t *testing.T) {
	// A whole-cluster survey (no namespace) lumps components; exposure is not proposed.
	cs := fake.NewSimpleClientset(
		pod("prod", "a", "repo/x:1"),
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "www", Namespace: "prod"}},
	)
	frag, _ := withClient(cs).Survey(context.Background(), plugin.SurveyScope{})
	if frag.Components[0].Exposure != "" {
		t.Errorf("whole-cluster survey should not propose exposure, got %q", frag.Components[0].Exposure)
	}
}
