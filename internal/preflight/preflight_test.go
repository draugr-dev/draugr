package preflight

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

// fakes records every probe call and answers from tables.
type fakes struct {
	mu        sync.Mutex
	calls     []string
	revisions map[string]error // url -> error; absent resolves to sha
	missing   map[string]bool  // path -> absent from the tree
	images    map[string]error
	clusters  map[string]error // kubeconfig context -> error; absent answers
}

func (f *fakes) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakes) probes() Probes {
	return Probes{
		Revision: func(_ context.Context, url, rev string) (string, error) {
			f.record("revision " + url + "@" + rev)
			if err := f.revisions[url]; err != nil {
				return "", err
			}
			return sha, nil
		},
		Paths: func(_ context.Context, url, rev string, paths []string) (string, error) {
			f.record("paths " + url + "@" + rev + " " + strings.Join(paths, ","))
			var gone []string
			for _, p := range paths {
				if f.missing[p] {
					gone = append(gone, p)
				}
			}
			if len(gone) > 0 {
				return "", fmt.Errorf("not in the tree at %s: %s", rev[:12], strings.Join(gone, ", "))
			}
			return rev, nil
		},
		Image: func(_ context.Context, ref string, offline bool) (string, error) {
			f.record("image " + ref)
			return probeImage(context.Background(), ref, offline,
				func(context.Context, string) bool { return strings.HasPrefix(ref, "local/") },
				func(context.Context, string) error { return f.images[ref] })
		},
		Cluster: func(_ context.Context, kubeCtx string) (string, error) {
			f.record("cluster " + kubeCtx)
			if err := f.clusters[kubeCtx]; err != nil {
				return "", err
			}
			return "context " + kubeCtx + " · Kubernetes v1.34.0", nil
		},
		Host: func(_ context.Context, raw string) (string, error) {
			f.record("host " + raw)
			if strings.Contains(raw, "down") {
				return "", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
			}
			return "TLS handshake completes", nil
		},
	}
}

func count(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func TestRunChecksEachDistinctTargetOnce(t *testing.T) {
	f := &fakes{missing: map[string]bool{"services/api": true}, images: map[string]error{
		"ghcr.io/acme/private:1": errors.New("401 unauthorized, no credential for ghcr.io"),
	}}
	targets := []plugin.Target{
		// Two components sharing one repository at one revision, scoped to different paths.
		plugin.RepositoryTarget{URL: "https://github.com/acme/mono.git", Revision: "main", Paths: []string{"services/web/**"}},
		plugin.RepositoryTarget{URL: "https://github.com/acme/mono.git", Revision: "main", Paths: []string{"services/api"}},
		// The same scope named again by a second control.
		plugin.RepositoryTarget{URL: "https://github.com/acme/mono.git", Revision: "main", Paths: []string{"services/web"}},
		plugin.HostTarget{URL: "https://app.example.com"},
		plugin.RepositoryTarget{URL: "https://github.com/acme/lib.git"},
		plugin.ImageTarget{Ref: "local/web:dev"},
		plugin.ImageTarget{Ref: "local/web:dev"},
		plugin.ImageTarget{Ref: "ghcr.io/acme/private:1"},
		plugin.HostTarget{URL: "https://app.example.com"},
		// One cluster used whole by one component and by namespaces by another: one check.
		plugin.KubernetesTarget{Cluster: "prod", Context: "prod-admin"},
		plugin.KubernetesTarget{Cluster: "prod", Context: "prod-admin", Namespaces: []string{"payments"}},
	}
	checks := Run(context.Background(), targets, Options{Probes: f.probes(), Concurrency: 2})

	want := []Check{
		{"repository", "https://github.com/acme/mono.git@main", Passed, "resolves to 0123456789ab"},
		{"paths", "services/web", Passed, "in the tree at 0123456789ab"},
		{"paths", "services/api", Failed, "not in the tree at 0123456789ab: services/api"},
		{"repository", "https://github.com/acme/lib.git", Passed, "resolves to 0123456789ab"},
		{"image", "local/web:dev", Passed, "in the local Docker daemon"},
		{"image", "ghcr.io/acme/private:1", Failed, "401 unauthorized, no credential for ghcr.io"},
		{"host", "https://app.example.com", Passed, "TLS handshake completes"},
		{"cluster", "kubernetes/prod", Passed, "context prod-admin · Kubernetes v1.34.0"},
	}
	if !slices.Equal(checks, want) {
		t.Errorf("checks:\n got %v\nwant %v", checks, want)
	}
	if n := FailedCount(checks); n != 2 {
		t.Errorf("FailedCount = %d, want 2", n)
	}
	if n := count(f.calls, "revision https://github.com/acme/mono.git"); n != 1 {
		t.Errorf("the shared repository was resolved %d times, want once", n)
	}
	if n := count(f.calls, "image local/web:dev"); n != 1 {
		t.Errorf("the shared image was checked %d times, want once", n)
	}
	// Paths are read from the resolved commit, so both scopes see one tree.
	for _, c := range f.calls {
		if strings.HasPrefix(c, "paths ") && !strings.Contains(c, "@"+sha) {
			t.Errorf("paths read at a name rather than the commit: %s", c)
		}
	}
}

func TestRunRevisionFailure(t *testing.T) {
	f := &fakes{revisions: map[string]error{
		"https://x-access-token:s3cret@github.com/acme/web.git": errors.New(
			"exit status 128: fatal: repository 'https://x-access-token:s3cret@github.com/acme/web.git/' not found\nmore"),
	}}
	targets := []plugin.Target{plugin.RepositoryTarget{
		URL:      "https://x-access-token:s3cret@github.com/acme/web.git", // #nosec G101 -- a fake credential the check must redact
		Revision: "main",
		Paths:    []string{"web"},
	}}
	checks := Run(context.Background(), targets, Options{Probes: f.probes()})
	if len(checks) != 2 {
		t.Fatalf("got %v", checks)
	}
	if checks[0].Status != Failed || strings.Contains(checks[0].Detail+checks[0].Target, "s3cret") {
		t.Errorf("repository check %+v: want a failure with no credential in it", checks[0])
	}
	if checks[0].Detail != "exit status 128: fatal: repository 'https://github.com/acme/web.git/' not found" {
		t.Errorf("detail = %q", checks[0].Detail)
	}
	if checks[1].Status != NotChecked || checks[1].Detail != "the revision did not resolve" {
		t.Errorf("paths check %+v", checks[1])
	}
}

func TestRunPinnedCommit(t *testing.T) {
	f := &fakes{}
	checks := Run(context.Background(), []plugin.Target{
		plugin.RepositoryTarget{URL: "https://github.com/acme/web.git", Revision: sha},
	}, Options{Probes: f.probes()})
	if checks[0].Status != Passed || checks[0].Detail != "commit exists" {
		t.Errorf("pinned commit: %+v", checks[0])
	}
	if count(f.calls, "paths ") != 1 {
		t.Errorf("a pinned commit was not looked up: %v", f.calls)
	}

	// A pinned commit the repository does not hold fails, and so does nothing downstream.
	f = &fakes{}
	p := f.probes()
	p.Paths = func(context.Context, string, string, []string) (string, error) {
		return "", errors.New("commit 0123456789ab: not in the repository")
	}
	checks = Run(context.Background(), []plugin.Target{
		plugin.RepositoryTarget{URL: "https://github.com/acme/web.git", Revision: sha, Paths: []string{"web"}},
	}, Options{Probes: p})
	if checks[0].Status != Failed || checks[0].Detail != "commit 0123456789ab: not in the repository" {
		t.Errorf("absent commit: %+v", checks[0])
	}
	if checks[1].Status != NotChecked {
		t.Errorf("paths under an absent commit: %+v", checks[1])
	}
}

func TestRunOffline(t *testing.T) {
	local := t.TempDir()
	f := &fakes{}
	checks := Run(context.Background(), []plugin.Target{
		plugin.RepositoryTarget{URL: "https://github.com/acme/web.git", Paths: []string{"web"}},
		plugin.RepositoryTarget{URL: local},
		plugin.ImageTarget{Ref: "local/web:dev"},
		plugin.ImageTarget{Ref: "ghcr.io/acme/web:1"},
		plugin.HostTarget{URL: "https://app.example.com"},
	}, Options{Offline: true, Probes: f.probes()})

	status := map[string]Status{}
	for _, c := range checks {
		status[c.Kind+" "+c.Target] = c.Status
		if c.Status == NotChecked && c.Detail != offlineReason {
			t.Errorf("%s %s: detail %q, want %q", c.Kind, c.Target, c.Detail, offlineReason)
		}
	}
	want := map[string]Status{
		"repository https://github.com/acme/web.git": NotChecked,
		"paths web":                    NotChecked,
		"repository " + local:          Passed, // on this machine, so no network needed
		"image local/web:dev":          Passed, // the local daemon needs no network either
		"image ghcr.io/acme/web:1":     NotChecked,
		"host https://app.example.com": NotChecked,
	}
	for k, v := range want {
		if status[k] != v {
			t.Errorf("%s: %s, want %s", k, status[k], v)
		}
	}
	if count(f.calls, "host ") != 0 {
		t.Errorf("a host was dialed offline: %v", f.calls)
	}
}

func TestRunHostFailureAndTimeout(t *testing.T) {
	f := &fakes{}
	p := f.probes()
	slow := p.Host
	p.Host = func(ctx context.Context, raw string) (string, error) {
		if strings.Contains(raw, "slow") {
			<-ctx.Done()
			return "", ctx.Err()
		}
		return slow(ctx, raw)
	}
	checks := Run(context.Background(), []plugin.Target{
		plugin.HostTarget{URL: "https://down.example.com"},
		plugin.HostTarget{URL: "https://slow.example.com"},
	}, Options{Probes: p, Timeout: 50 * time.Millisecond})
	if checks[0].Status != Failed || checks[0].Detail != "connection refused" {
		t.Errorf("refused: %+v", checks[0])
	}
	if checks[1].Status != Failed || checks[1].Detail != "no answer before the timeout" {
		t.Errorf("timeout: %+v", checks[1])
	}
}

func TestReason(t *testing.T) {
	gitErr := func() error {
		err := exec.Command("sh", "-c", "echo 'fatal: could not read from https://u:p@git.example.com/r.git' >&2; exit 128").Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("want an ExitError, got %v", err)
		}
		exit.Stderr = []byte("fatal: could not read from https://u:p@git.example.com/r.git\nhint: more\n")
		return fmt.Errorf("git ls-remote: %w", exit)
	}()
	cases := []struct {
		name string
		err  error
		raw  string
		want string
	}{
		{"stderr, userinfo removed", gitErr, "https://u:p@git.example.com/r.git", "could not read from https://git.example.com/r.git"},
		{"userinfo in a URL not given", errors.New("GET https://tok@other.example.com/x failed"), "", "GET https://other.example.com/x failed"},
		{"dns", &url.Error{Op: "Head", URL: "https://r.example.com/v2/", Err: &net.OpError{Op: "dial", Net: "tcp",
			Err: &net.DNSError{Name: "r.example.com", Err: "no such host"}}}, "", "lookup r.example.com: no such host"},
		{"dial", &url.Error{Op: "Head", URL: "https://r.example.com/v2/", Err: &net.OpError{Op: "dial", Net: "tcp",
			Err: errors.New("connection refused")}}, "", "connection refused"},
		{"deadline", fmt.Errorf("fetch: %w", context.DeadlineExceeded), "", "no answer before the timeout"},
	}
	for _, c := range cases {
		if got := reason(c.err, c.raw); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestProbeImage(t *testing.T) {
	ctx := context.Background()
	absent := func(context.Context, string) bool { return false }
	ok := func(context.Context, string) error { return nil }
	if d, err := probeImage(ctx, "r/x:1", false, absent, ok); err != nil || d != "manifest readable" {
		t.Errorf("remote: %q %v", d, err)
	}
	if _, err := probeImage(ctx, "r/x:1", true, absent, ok); !errors.Is(err, errNotChecked) {
		t.Errorf("offline: %v", err)
	}
	refused := errors.New("403 forbidden")
	if _, err := probeImage(ctx, "r/x:1", false, absent, func(context.Context, string) error { return refused }); !errors.Is(err, refused) {
		t.Errorf("refused: %v", err)
	}
}

func TestDialHost(t *testing.T) {
	ctx := context.Background()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if d, err := dialHost(ctx, "http://"+ln.Addr().String()); err != nil || d != "connects" {
		t.Errorf("plain: %q %v", d, err)
	}

	// httptest's certificate is not one this machine trusts: reachable, and said to be untrusted.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	d, err := dialHost(ctx, srv.URL)
	if err != nil || !strings.HasPrefix(d, "connects, certificate not trusted: ") {
		t.Errorf("untrusted TLS: %q %v", d, err)
	}

	closed := ln.Addr().String()
	_ = ln.Close()
	if _, err := dialHost(ctx, "http://"+closed); err == nil {
		t.Error("a closed port connected")
	}
	if _, err := dialHost(ctx, "ftp://example.com"); err == nil {
		t.Error("a URL with no port for its scheme passed")
	}
	if _, err := dialHost(ctx, "://bad"); err == nil {
		t.Error("an unparseable URL passed")
	}
}

func TestLocalImageWithoutDocker(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if localImage(context.Background(), "nginx:1") {
		t.Error("an image was found with no docker on PATH")
	}
}

// A cluster whose context does not resolve, or whose API server does not answer, fails before a
// scan does, naming the cluster; --offline leaves it unchecked rather than passed.
func TestAClusterThatCannotBeReachedFails(t *testing.T) {
	f := &fakes{clusters: map[string]error{"gone": errors.New(`no kubeconfig context named "gone" (it has prod-admin)`)}}
	checks := Run(context.Background(), []plugin.Target{plugin.KubernetesTarget{Cluster: "old", Context: "gone"}},
		Options{Probes: f.probes()})
	want := []Check{{"cluster", "kubernetes/old", Failed, `no kubeconfig context named "gone" (it has prod-admin)`}}
	if !slices.Equal(checks, want) {
		t.Errorf("checks = %v, want %v", checks, want)
	}
	checks = Run(context.Background(), []plugin.Target{plugin.KubernetesTarget{Cluster: "prod"}},
		Options{Probes: f.probes(), Offline: true})
	if len(checks) != 1 || checks[0].Status != NotChecked || checks[0].Detail != offlineReason {
		t.Errorf("offline = %v, want not checked", checks)
	}
	if n := count(f.calls, "cluster "); n != 1 {
		t.Errorf("cluster probes = %d, want only the online one", n)
	}
}

// The context a cluster is reached through: the one named, or the kubeconfig's current one.
func TestResolveContext(t *testing.T) {
	raw := &clientcmdapi.Config{
		CurrentContext: "dev",
		Contexts:       map[string]*clientcmdapi.Context{"dev": {}, "prod-admin": {}},
	}
	for kubeCtx, want := range map[string]string{"": "dev", "prod-admin": "prod-admin"} {
		if got, err := resolveContext(raw, kubeCtx); err != nil || got != want {
			t.Errorf("resolveContext(%q) = %q, %v; want %q", kubeCtx, got, err, want)
		}
	}
	if _, err := resolveContext(raw, "gone"); err == nil || !strings.Contains(err.Error(), "dev, prod-admin") {
		t.Errorf("an unknown context: %v, want the ones the kubeconfig has", err)
	}
	if _, err := resolveContext(&clientcmdapi.Config{}, ""); err == nil || !strings.Contains(err.Error(), "no current context") {
		t.Errorf("no current context: %v", err)
	}
	many := &clientcmdapi.Config{Contexts: map[string]*clientcmdapi.Context{}}
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		many.Contexts[n] = &clientcmdapi.Context{}
	}
	if _, err := resolveContext(many, "z"); err == nil || !strings.Contains(err.Error(), "and 2 more") {
		t.Errorf("a long list is not capped: %v", err)
	}
}
