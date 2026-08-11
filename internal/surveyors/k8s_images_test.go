package surveyors

import (
	"context"
	"errors"
	"slices"
	"strings"
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

// ns builds the Namespace object a fixture implies. A fake cluster with pods in a namespace that
// does not exist is not a shape a real cluster can be in, and leaving it out made the fixtures
// disagree with the thing they stand in for.
func ns(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func withClient(cs kubernetes.Interface) K8sImages {
	return K8sImages{clientset: func(plugin.SurveyScope) (kubernetes.Interface, error) { return cs, nil }}
}

// podWithDigests builds a pod whose containers each have a running status carrying an
// ImageID, so the surveyor can capture the content digest. imgToID maps container image ref
// → ImageID (as a runtime would report it).
func podWithDigests(ns, name string, imgToID map[string]string) *corev1.Pod {
	var (
		containers []corev1.Container
		statuses   []corev1.ContainerStatus
		i          int
	)
	for img, id := range imgToID {
		cname := name + "-c" + string(rune('a'+i))
		i++
		containers = append(containers, corev1.Container{Name: cname, Image: img})
		statuses = append(statuses, corev1.ContainerStatus{Name: cname, Image: img, ImageID: id})
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.PodSpec{Containers: containers},
		Status:     corev1.PodStatus{ContainerStatuses: statuses},
	}
}

func TestDigestFromImageID(t *testing.T) {
	cases := map[string]string{
		"docker-pullable://repo/x@sha256:abc": "sha256:abc",
		"repo/x@sha256:def":                   "sha256:def",
		"sha256:bare":                         "sha256:bare",
		"repo/x:1.0":                          "", // tag only, no digest
		"":                                    "",
	}
	for in, want := range cases {
		if got := digestFromImageID(in); got != want {
			t.Errorf("digestFromImageID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestK8sImagesSurveyCapturesDigest(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ns("prod"),
		podWithDigests("prod", "a", map[string]string{
			"repo/x:1": "docker-pullable://repo/x@sha256:aaa",
		}),
	)
	frag, err := withClient(cs).Survey(context.Background(), plugin.SurveyScope{Ref: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	imgs := frag.Components[0].Images
	if len(imgs) != 1 {
		t.Fatalf("want 1 image, got %d", len(imgs))
	}
	if imgs[0].Image != "repo/x:1" || imgs[0].Digest != "sha256:aaa" {
		t.Errorf("image = %+v, want ref repo/x:1 + digest sha256:aaa", imgs[0])
	}
}

func TestK8sImagesInfo(t *testing.T) {
	if NewK8sImages().Info().Name != "k8s-images" {
		t.Error("wrong name")
	}
}

func TestK8sImagesSurveyDedups(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ns("prod"),
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

// A survey with no namespace describes every namespace, one component each — the same shape
// `--namespace a,b` produces, for all of them rather than the two you happened to name.
//
// Three namespaces rather than one, because one cannot tell a per-namespace answer from a
// collapsed one: with a single namespace, "the whole cluster" and "that namespace" are the same
// set of images under the same name, and every arrangement looks correct.
func TestK8sImagesWithoutANamespaceReturnsOneComponentPerNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ns("alpha"), ns("beta"), ns("gamma"),
		pod("alpha", "a", "repo/a:1"),
		pod("beta", "b", "repo/b:1"),
		pod("gamma", "c", "repo/c:1"),
	)
	frag, err := withClient(cs).Survey(context.Background(), plugin.SurveyScope{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range frag.Components {
		got = append(got, c.Name)
	}
	// Sorted, so a re-survey does not reorder the descriptor and turn every run into a diff.
	if want := []string{"alpha", "beta", "gamma"}; !slices.Equal(got, want) {
		t.Fatalf("components = %v, want %v", got, want)
	}
	for _, c := range frag.Components {
		if len(c.Images) != 1 {
			t.Errorf("component %q should carry only its own images, got %+v", c.Name, c.Images)
		}
	}
}

func TestK8sImagesNoPods(t *testing.T) {
	frag, err := withClient(fake.NewSimpleClientset(ns("empty"))).Survey(context.Background(), plugin.SurveyScope{Ref: "empty"})
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

func TestImagesByNamespaceIncludesInitContainers(t *testing.T) {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init", Image: "init:1"}},
			Containers:     []corev1.Container{{Name: "app", Image: "app:1"}},
		},
	}
	if imgs := imagesByNamespace([]corev1.Pod{*p})["prod"]; len(imgs) != 2 {
		t.Fatalf("want init + app images, got %+v", imgs)
	}
}

// The same image in two namespaces is two components' surface. Deduplicating across them would
// leave one of the two describing an image it runs, and the engine collapses identical targets
// when it plans, so the honest descriptor costs nothing to scan.
func TestImagesByNamespaceKeepsAnImageSharedByTwoNamespaces(t *testing.T) {
	shared := func(ns string) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "repo/x:1"}}},
		}
	}
	got := imagesByNamespace([]corev1.Pod{shared("a"), shared("b")})
	for _, ns := range []string{"a", "b"} {
		if len(got[ns]) != 1 || got[ns][0].Image != "repo/x:1" {
			t.Errorf("namespace %q lost the image it runs: %+v", ns, got[ns])
		}
	}
}

func TestInferExposurePublicFromIngress(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ns("prod"),
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
		ns("prod"),
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
		ns("prod"),
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
	cs := fake.NewSimpleClientset(ns("prod"), pod("prod", "a", "repo/x:1")) // no ingress/svc/netpol
	frag, _ := withClient(cs).Survey(context.Background(), plugin.SurveyScope{Ref: "prod"})
	if frag.Components[0].Exposure != saga.ExposureInternal {
		t.Errorf("no topology signal → exposure = %q, want internal", frag.Components[0].Exposure)
	}
}

// Exposure is proposed per namespace even when no namespace was asked for, and it belongs to the
// namespace whose topology implies it.
//
// The Ingress is in one namespace only. Inference that answered per cluster would mark both
// public — which is the reason a lumped component could not carry an exposure at all, and the
// reason this has to be checked with a namespace that has no route as well as one that does.
func TestExposureIsProposedPerNamespaceAcrossAWholeCluster(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ns("front"), ns("back"),
		pod("front", "a", "repo/a:1"),
		pod("back", "b", "repo/b:1"),
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "www", Namespace: "front"}},
	)
	frag, err := withClient(cs).Survey(context.Background(), plugin.SurveyScope{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]saga.Exposure{"back": saga.ExposureInternal, "front": saga.ExposurePublic}
	for _, c := range frag.Components {
		if c.Exposure != want[c.Name] {
			t.Errorf("%s exposure = %q, want %q", c.Name, c.Exposure, want[c.Name])
		}
	}
}

// Listing pods in a namespace that is not there returns an empty list rather than an error, so a
// typo produced a survey that succeeded, discovered nothing from that namespace, and said nothing
// about it. Ask for three namespaces, misspell one, and the descriptor quietly describes two —
// which becomes the scope of every later scan.
func TestASurveyFailsOnANamespaceThatDoesNotExist(t *testing.T) {
	cs := fake.NewSimpleClientset(ns("prod"), pod("prod", "a", "repo/x:1"))
	_, err := withClient(cs).Survey(context.Background(), plugin.SurveyScope{Ref: "prd"})
	if err == nil {
		t.Fatal("a misspelt namespace surveyed silently")
	}
	if !strings.Contains(err.Error(), "prd") {
		t.Errorf("the error must name the namespace: %v", err)
	}
}

// The whole cluster has no namespace to check.
func TestAnUnscopedSurveyChecksNoNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset(pod("anywhere", "a", "repo/x:1"))
	if _, err := withClient(cs).Survey(context.Background(), plugin.SurveyScope{}); err != nil {
		t.Errorf("an unscoped survey should not need a namespace to exist: %v", err)
	}
}
