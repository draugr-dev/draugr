package surveyors

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// requireNamespace fails when a namespace the operator named does not exist.
//
// Listing pods in a namespace that is not there returns an empty list rather than an error, so a
// typo produces a survey that succeeds, discovers nothing from that namespace, and says nothing
// about it. Ask for three namespaces, misspell one, and the descriptor quietly describes two —
// which is the scope of every later scan, and nothing in the file records that a third was
// intended.
//
// An error rather than a warning: the surveyor registry gathers what the other requests found and
// reports this alongside it, so a mistyped namespace is loud without discarding the survey that
// worked.
//
// An empty ref means the whole cluster and has nothing to check.
func requireNamespace(ctx context.Context, cs kubernetes.Interface, name string) error {
	if name == "" {
		return nil
	}
	_, err := cs.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	switch {
	case err == nil:
		return nil
	case apierrors.IsNotFound(err):
		return fmt.Errorf("namespace %q does not exist in this cluster", name)
	case apierrors.IsForbidden(err):
		// A credential scoped to a namespace often cannot read the namespace object itself. That
		// is a normal way to be configured, not a mistake, so it must not fail the survey — the
		// listing that follows will report its own permission error if there is one.
		return nil
	default:
		return fmt.Errorf("check namespace %q: %w", name, err)
	}
}
