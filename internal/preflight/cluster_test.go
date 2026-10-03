package preflight

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// kubeconfig writes a kubeconfig with one context per server and points KUBECONFIG at it.
func kubeconfig(t *testing.T, current string, servers map[string]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\ncurrent-context: " + current + "\nclusters:\n")
	for name, url := range servers {
		fmt.Fprintf(&b, "- name: %s\n  cluster:\n    server: %s\n", name, url)
	}
	b.WriteString("contexts:\n")
	for name := range servers {
		fmt.Fprintf(&b, "- name: %s\n  context:\n    cluster: %s\n    user: u\n", name, name)
	}
	b.WriteString("users:\n- name: u\n  user: {}\n")
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
}

// The real probe, against a server that answers like an API server: the named context resolves
// and the version is read from it; with none named, the current context is the one asked.
func TestReachClusterAsksTheContextsAPIServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"major":"1","minor":"34","gitVersion":"v1.34.0"}`))
	}))
	defer srv.Close()
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()
	kubeconfig(t, "dev", map[string]string{"dev": srv.URL, "prod-admin": srv.URL, "gone": downURL})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for kubeCtx, want := range map[string]string{
		"prod-admin": "context prod-admin · Kubernetes v1.34.0",
		"":           "context dev · Kubernetes v1.34.0",
	} {
		got, err := reachCluster(ctx, kubeCtx)
		if err != nil || got != want {
			t.Errorf("reachCluster(%q) = %q, %v; want %q", kubeCtx, got, err, want)
		}
	}
	if _, err := reachCluster(ctx, "staging"); err == nil || !strings.Contains(err.Error(), `no kubeconfig context named "staging"`) {
		t.Errorf("an unknown context: %v", err)
	}
	if _, err := reachCluster(ctx, "gone"); err == nil || !strings.Contains(err.Error(), "the API server did not answer") {
		t.Errorf("a server that is not there: %v", err)
	}
}

// With no probe supplied, the real one is used, so doctor cannot quietly skip clusters.
func TestTheClusterProbeDefaultsToTheRealOne(t *testing.T) {
	if p := (Probes{}).withDefaults(); p.Cluster == nil || p.Host == nil || p.Image == nil {
		t.Error("withDefaults left a probe unset")
	}
}
