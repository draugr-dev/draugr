package surveyors

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// namespaceGet returns a clientset whose namespace reads fail with err.
func namespaceGet(err error) *fake.Clientset {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, err
	})
	return cs
}

func TestRequireNamespace(t *testing.T) {
	t.Parallel()

	gr := schema.GroupResource{Resource: "namespaces"}
	tests := []struct {
		name    string
		cs      *fake.Clientset
		ref     string
		wantErr string
	}{
		{
			// The whole cluster. There is nothing to check, and checking would need a permission
			// a cluster-wide survey does not otherwise require.
			name: "an empty ref means the whole cluster",
			cs:   namespaceGet(errors.New("should not be called")),
			ref:  "",
		},
		{
			name: "a namespace that exists",
			cs:   fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}),
			ref:  "team-a",
		},
		{
			// The case this function exists for: listing pods in a namespace that is not there
			// returns an empty list, so without this a typo surveys nothing and says nothing.
			name:    "a namespace that does not exist",
			cs:      namespaceGet(apierrors.NewNotFound(gr, "team-b")),
			ref:     "team-b",
			wantErr: `namespace "team-b" does not exist in this cluster`,
		},
		{
			// A credential scoped to one namespace commonly cannot read the namespace object
			// itself. Failing here would reject a normal configuration, and the listing that
			// follows reports its own permission error if there is really no access.
			name: "no permission to read the namespace object",
			cs:   namespaceGet(apierrors.NewForbidden(gr, "team-c", errors.New("nope"))),
			ref:  "team-c",
		},
		{
			// Anything else is unknown, and an unknown answer is not a yes.
			name:    "the cluster could not answer",
			cs:      namespaceGet(errors.New("connection refused")),
			ref:     "team-d",
			wantErr: `check namespace "team-d": connection refused`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := requireNamespace(context.Background(), tc.cs, tc.ref)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want no error, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want error %q, got none", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
