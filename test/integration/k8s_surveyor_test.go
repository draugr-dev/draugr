//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/draugr-dev/draugr/internal/surveyors"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// integrationImage is a small, pinned public image the surveyor should discover, chosen old
// enough to be stable. It runs `sleep` so the pod stays Running long enough to read its
// container status (where the resolved digest lives).
const integrationImage = "alpine:3.14"

// clientset builds a Kubernetes client from the ambient kubeconfig (the kind cluster the
// integration workflow provisions). Same resolution the surveyor uses internally.
func clientset(t *testing.T) kubernetes.Interface {
	t.Helper()
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("build kube client config (is a cluster reachable?): %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("build kube clientset: %v", err)
	}
	return cs
}

// TestK8sImagesSurveyor deploys a known pod to a real cluster and runs the k8s-images
// surveyor against it, proving the real client-go wiring (which unit tests fake) — including
// the running-image digest capture read from the pod's container status.
func TestK8sImagesSurveyor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cs := clientset(t)
	const ns = "draugr-integration"

	// Fresh namespace; clean up afterwards.
	_, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{})
	})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   integrationImage,
				Command: []string{"sleep", "3600"},
			}},
		},
	}
	if _, err := cs.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create pod: %v", err)
	}

	// Wait for the pod to be Running with a resolved image digest in its status.
	if err := waitForRunningDigest(ctx, cs, ns, "target"); err != nil {
		t.Fatalf("pod never reached Running with a digest: %v", err)
	}

	// Run the surveyor exactly as the CLI does (it builds its own client from the ambient
	// kubeconfig), scoped to our namespace.
	frag, err := surveyors.NewK8sImages().Survey(ctx, plugin.SurveyScope{Ref: ns})
	if err != nil {
		t.Fatalf("survey: %v", err)
	}
	if len(frag.Components) != 1 {
		t.Fatalf("want 1 component, got %d: %+v", len(frag.Components), frag.Components)
	}
	imgs := frag.Components[0].Images
	if len(imgs) != 1 {
		t.Fatalf("want 1 discovered image, got %d: %+v", len(imgs), imgs)
	}
	if imgs[0].Image != integrationImage {
		t.Errorf("discovered image = %q, want %q", imgs[0].Image, integrationImage)
	}
	if !strings.HasPrefix(imgs[0].Digest, "sha256:") {
		t.Errorf("discovered digest = %q, want a captured sha256: digest", imgs[0].Digest)
	}
}

// waitForRunningDigest polls until the named pod is Running and its container status reports
// a resolved image (ImageID), which is where the surveyor reads the digest.
func waitForRunningDigest(ctx context.Context, cs kubernetes.Interface, ns, name string) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		pod, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err == nil && pod.Status.Phase == corev1.PodRunning {
			for _, s := range pod.Status.ContainerStatuses {
				if strings.Contains(s.ImageID, "@sha256:") || strings.HasPrefix(s.ImageID, "sha256:") {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
