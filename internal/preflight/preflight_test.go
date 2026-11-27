package preflight

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	if LocalImage(context.Background(), "nginx:1") {
		t.Error("an image was found with no docker on PATH")
	}
}

// fakeDaemon is a daemonProbe over a docker CLI and a daemon API that answer as told.
type fakeDaemon struct {
	cli     bool            // docker is on PATH
	ran     map[string]bool // first argument after "docker" → whether it succeeded
	env     map[string]string
	ping    int // the API's answer to /_ping, 0 for no answer
	image   int // the API's answer for the image
	apiHost string
}

func (f *fakeDaemon) probe() daemonProbe {
	return daemonProbe{
		lookPath: func(string) (string, error) {
			if f.cli {
				return "/usr/bin/docker", nil
			}
			return "", exec.ErrNotFound
		},
		run: func(_ context.Context, args ...string) error {
			if f.ran[args[1]] {
				return nil
			}
			return errors.New("exit status 1")
		},
		getenv: func(k string) string { return f.env[k] },
		api: func(_ context.Context, host, path string) (int, error) {
			f.apiHost = host
			code := f.image
			if path == "/_ping" {
				code = f.ping
			}
			if code == 0 {
				return 0, errors.New("dial unix /var/run/docker.sock: connect: no such file or directory")
			}
			return code, nil
		},
	}
}

// The daemon is asked through the docker CLI where there is one, and on its socket where there is
// not, as Trivy reads it in a container with the socket mounted. Only a daemon that did not answer
// is reported unreachable; one this machine cannot ask counts as reachable, so a refusal is never
// blamed on a daemon that may be there.
func TestTheDaemonSaysWhetherItHoldsTheImageAndWhetherItAnswered(t *testing.T) {
	for _, c := range []struct {
		name            string
		f               fakeDaemon
		held, reachable bool
		wantHost        string
	}{
		{"cli, held", fakeDaemon{cli: true, ran: map[string]bool{"image": true}}, true, true, ""},
		{"cli, daemon lacks it", fakeDaemon{cli: true, ran: map[string]bool{"version": true}}, false, true, ""},
		{"cli, no daemon", fakeDaemon{cli: true}, false, false, ""},
		{"socket, held", fakeDaemon{ping: 200, image: 200}, true, true, "unix:///var/run/docker.sock"},
		{"socket, daemon lacks it", fakeDaemon{ping: 200, image: 404}, false, true, "unix:///var/run/docker.sock"},
		{"no socket", fakeDaemon{}, false, false, "unix:///var/run/docker.sock"},
		{"socket answers, not a daemon", fakeDaemon{ping: 404}, false, false, "unix:///var/run/docker.sock"},
		{"DOCKER_HOST over tcp", fakeDaemon{env: map[string]string{"DOCKER_HOST": "tcp://docker:2375"}, ping: 200, image: 200},
			true, true, "tcp://docker:2375"},
		{"DOCKER_HOST behind TLS", fakeDaemon{env: map[string]string{"DOCKER_HOST": "tcp://docker:2376", "DOCKER_TLS_VERIFY": "1"}},
			false, true, ""},
		{"DOCKER_HOST over ssh", fakeDaemon{env: map[string]string{"DOCKER_HOST": "ssh://me@build"}}, false, true, ""},
	} {
		held, reachable := c.f.probe().look(context.Background(), "app:1")
		if held != c.held || reachable != c.reachable || c.f.apiHost != c.wantHost {
			t.Errorf("%s: held %v, reachable %v, asked %q; want %v, %v, %q",
				c.name, held, reachable, c.f.apiHost, c.held, c.reachable, c.wantHost)
		}
	}
}

// The daemon's API is asked over its socket and over plain tcp, with the status passed through.
func TestTheDaemonAPIIsAskedOnItsSocketAndOverTCP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" || r.URL.Path == "/images/app:1/json" {
			_, _ = w.Write([]byte("OK"))
			return
		}
		http.NotFound(w, r)
	})
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	tcp := httptest.NewServer(handler)
	t.Cleanup(tcp.Close)

	ctx := context.Background()
	for _, host := range []string{"unix://" + sock, "tcp://" + strings.TrimPrefix(tcp.URL, "http://")} {
		if code, err := daemonAPI(ctx, host, "/_ping"); err != nil || code != http.StatusOK {
			t.Errorf("%s: ping = %d, %v", host, code, err)
		}
		if code, err := daemonAPI(ctx, host, "/images/gone:1/json"); err != nil || code != http.StatusNotFound {
			t.Errorf("%s: a missing image = %d, %v", host, code, err)
		}
	}
	if _, err := daemonAPI(ctx, "unix://"+filepath.Join(t.TempDir(), "none.sock"), "/_ping"); err == nil {
		t.Error("a socket nobody listens on answered")
	}
	if _, err := daemonAPI(ctx, "tcp://bad host", "/_ping"); err == nil {
		t.Error("an address that is not one answered")
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

// doctor says before the scan whether an imported file is there and is SARIF 2.1.0, because the
// scan stops on either.
func TestDoctorChecksAnImportedFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		path   string
		status Status
		detail string
	}{
		{write("ok.sarif", `{"version":"2.1.0","runs":[{"results":[{"ruleId":"a"}]},{"results":[{"ruleId":"b"}]}]}`), Passed, "SARIF 2.1.0, 2 results"},
		// Valid SARIF that a reader of Draugr's own file refused: a numeric security-severity and
		// property names Draugr uses for something else.
		{write("numeric.sarif", `{"version":"2.1.0","runs":[{"results":[{"ruleId":"a",`+
			`"properties":{"security-severity":7.5,"priority":3,"labels":["x"],"package":"lib"}}]}]}`), Passed, "SARIF 2.1.0, 1 result"},
		{write("old.sarif", `{"version":"2.0.0","runs":[]}`), Failed, `states SARIF version "2.0.0"`},
		{write("empty.sarif", `{"version":"2.1.0","runs":[]}`), Failed, "holds no runs"},
		{write("junk.sarif", `junk`), Failed, "not a SARIF log"},
		// A file the scan refuses fails here with the scan's words.
		{write("badrule.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{"id":"r"}]}},`+
			`"results":[{"ruleIndex":4}]}]}`), Failed, "run 1, result 1: ruleIndex 4 is not an entry of tool.driver.rules, which has 1 rule (index 0)"},
		{filepath.Join(dir, "absent.sarif"), Failed, "no such file"},
	} {
		got := Run(context.Background(), []plugin.Target{plugin.FileTarget{Path: c.path}, plugin.FileTarget{Path: c.path}}, Options{Offline: true})
		if len(got) != 1 || got[0].Status != c.status || !strings.Contains(got[0].Detail, c.detail) || got[0].Kind != "file" {
			t.Errorf("%s: %+v, want %v %q, checked once", filepath.Base(c.path), got, c.status, c.detail)
		}
	}
}

// An import of GitHub's alerts or SonarQube's issues is checked for the token it will send, once per
// source, project, repository and variable, without reaching the service: the variable has to be one
// it may read, and set. SonarQube's row names the server the token goes to.
func TestDoctorChecksASourcesToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("b", 36))
	t.Setenv("SONAR_TOKEN", "sqp_"+strings.Repeat("b", 40))
	t.Setenv("SONAR_HOST_URL", "")
	t.Setenv("DRAUGR_TOKEN_ENVS", "")
	code := plugin.FileTarget{Source: "github-code-scanning", Repository: "acme/api"}
	got := Run(context.Background(), []plugin.Target{
		code, code,
		plugin.FileTarget{Source: "github-dependabot", Repository: "acme/api", TokenEnv: "OTHER_TOKEN"},
		plugin.FileTarget{Source: "sonarqube", Project: "acme_api"},
		plugin.FileTarget{Source: "sonarqube", Project: "acme_api"},
	}, Options{Offline: true})
	if len(got) != 3 {
		t.Fatalf("%d checks, want one per source and variable: %+v", len(got), got)
	}
	for _, c := range got {
		switch c.Target {
		case "github-code-scanning acme/api":
			if c.Status != Passed || c.Detail != "token in $GITHUB_TOKEN, alerts read by the scan" {
				t.Errorf("code scanning check %+v", c)
			}
		case "github-dependabot acme/api":
			if c.Status != Failed || !strings.Contains(c.Detail, "$OTHER_TOKEN is not listed in $DRAUGR_TOKEN_ENVS") {
				t.Errorf("dependabot check %+v", c)
			}
		case "sonarqube acme_api":
			if c.Kind != "issues" || c.Status != Passed ||
				c.Detail != "token in $SONAR_TOKEN, findings read from https://sonarcloud.io by the scan" {
				t.Errorf("sonarqube check %+v", c)
			}
		default:
			t.Errorf("unexpected check %+v", c)
		}
		if strings.Contains(c.Detail, "ghp_") || strings.Contains(c.Detail, "sqp_") {
			t.Errorf("the token is in %+v", c)
		}
	}
}

// A tool's own JSON is checked by the reader its format names, once per file and format, so a file
// imported as one format and read as another fails doctor as it would fail the scan.
func TestDoctorChecksAnImportedFileAsItsFormat(t *testing.T) {
	trivy := filepath.Join(t.TempDir(), "trivy.json")
	doc := `{"SchemaVersion":2,"Results":[{"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[` +
		`{"VulnerabilityID":"CVE-2026-0001","PkgName":"a","InstalledVersion":"1.0.0","Severity":"HIGH"}]}]}`
	if err := os.WriteFile(trivy, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Run(context.Background(), []plugin.Target{
		plugin.FileTarget{Path: trivy, Format: "trivy-json"},
		plugin.FileTarget{Path: trivy, Format: "trivy-json"},
		plugin.FileTarget{Path: trivy, Format: "govulncheck-json"},
	}, Options{Offline: true})
	if len(got) != 2 {
		t.Fatalf("%d checks, want one per format: %+v", len(got), got)
	}
	details := map[Status]string{}
	for _, c := range got {
		details[c.Status] = c.Detail
	}
	if details[Passed] != "Trivy JSON, 1 finding, commit not stated. The scan lists it under unbound-imports" || !strings.Contains(details[Failed], "not govulncheck JSON") {
		t.Errorf("checks %+v", got)
	}
}

// A file that holds several controls' results is checked once for each control it is imported into,
// each row naming the control and counting that control's findings, since each import reads its own.
func TestDoctorChecksAFileOncePerControlItIsReadInto(t *testing.T) {
	cx := filepath.Join(t.TempDir(), "cx_result.json")
	doc := `{"results":[` +
		`{"type":"sast","severity":"HIGH","data":{"queryName":"SQL_Injection","nodes":[{"line":3,"fileName":"/a.java"}]}},` +
		`{"type":"kics","severity":"LOW","data":{"queryId":"q-1","filename":"/main.tf","line":1}},` +
		`{"type":"kics","severity":"LOW","data":{"queryId":"q-2","filename":"/main.tf","line":2}}],` +
		`"totalCount":3,"scanID":"s"}`
	if err := os.WriteFile(cx, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	at := func(control string) plugin.FileTarget {
		return plugin.FileTarget{Path: cx, Component: "api", Format: "checkmarx-one-json", Control: control}
	}
	got := Run(context.Background(), []plugin.Target{at("sast"), at("iac"), at("iac")}, Options{Offline: true})
	rows := map[string]string{}
	for _, c := range got {
		rows[c.Target] = c.Detail
	}
	unbound := ", commit not stated. The scan lists it under unbound-imports"
	if len(got) != 2 || rows[cx+" · api · sast"] != "Checkmarx One JSON, 1 finding"+unbound ||
		rows[cx+" · api · iac"] != "Checkmarx One JSON, 2 findings"+unbound {
		t.Errorf("checks %+v", got)
	}
}

// doctor holds an imported file to the commit the scan reads, by the scan's rule, because the scan
// stops on a file written for another commit: the same commit passes, abbreviated too, another fails
// in the scan's words, a variable left unset and a file naming neither of two repositories show as
// unbound, and offline a remote repository's branch is not resolved.
func TestDoctorHoldsAnImportedFileToTheCommit(t *testing.T) {
	const (
		firstHead  = "0123456789abcdef0123456789abcdef01234567"
		secondHead = "89abcdef0123456789abcdef0123456789abcdef"
	)
	dir := t.TempDir()
	write := func(name, provenance string) string {
		p := filepath.Join(dir, name)
		body := `{"version":"2.1.0","runs":[{` + provenance + `"results":[{"ruleId":"a"}]}]}`
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stated := func(uri, rev string) string {
		return `"versionControlProvenance":[{"repositoryUri":"` + uri + `","revisionId":"` + rev + `"}],`
	}
	plain := write("plain.sarif", "")
	one := []plugin.RepositoryTarget{{URL: "https://github.com/acme/api", Revision: "main"}}
	two := []plugin.RepositoryTarget{{URL: "https://github.com/acme/api", Revision: "main"}, {URL: "https://github.com/acme/web", Revision: "main"}}
	probes := Probes{Revision: func(_ context.Context, url, _ string) (string, error) {
		if strings.HasSuffix(url, "/web") {
			return secondHead, nil
		}
		return firstHead, nil
	}}
	for _, c := range []struct {
		name    string
		target  plugin.FileTarget
		offline bool
		status  Status
		detail  string
	}{
		{"the file's own commit", plugin.FileTarget{Path: write("same.sarif", stated("https://github.com/acme/api", firstHead)), Repositories: one},
			false, Passed, "SARIF 2.1.0, 1 result, commit 0123456789ab"},
		{"the descriptor's commit, abbreviated", plugin.FileTarget{Path: plain, Repositories: one, Commit: firstHead[:7]},
			false, Passed, "SARIF 2.1.0, 1 result, commit 0123456789ab"},
		{"another commit", plugin.FileTarget{Path: plain, Repositories: one, Commit: secondHead},
			false, Failed, "scanned 89abcdef0123, this run reads 0123456789ab. Run the tool again"},
		{"an unset variable", plugin.FileTarget{Path: plain, Repositories: one, CommitUnset: "GITHUB_SHA"},
			false, Passed, "SARIF 2.1.0, 1 result, commit not stated, ${{ GITHUB_SHA }} is not set. The scan lists it under unbound-imports"},
		{"the second of two repositories", plugin.FileTarget{Path: write("web.sarif", stated("https://github.com/acme/web", secondHead)), Repositories: two},
			false, Passed, "commit 89abcdef0123"},
		{"the first's commit for the second", plugin.FileTarget{Path: write("web-old.sarif", stated("https://github.com/acme/web", firstHead)), Repositories: two},
			false, Failed, "scanned 0123456789ab, this run reads 89abcdef0123"},
		{"two repositories, the file naming neither", plugin.FileTarget{Path: plain, Repositories: two, Commit: secondHead},
			false, Passed, "commit not stated, the file names none or several of the component's repositories"},
		{"offline, a remote branch", plugin.FileTarget{Path: plain, Repositories: one, Commit: firstHead},
			true, NotChecked, "SARIF 2.1.0, 1 result, commit not checked under --offline"},
		{"offline, a file read but refused", plugin.FileTarget{Path: write("junk.sarif", `"x":`), Repositories: one, Commit: firstHead},
			true, Failed, "not a SARIF log"},
	} {
		got := Run(context.Background(), []plugin.Target{c.target}, Options{Offline: c.offline, Probes: probes})
		if len(got) != 1 || got[0].Status != c.status || !strings.Contains(got[0].Detail, c.detail) {
			t.Errorf("%s: %+v, want %v %q", c.name, got, c.status, c.detail)
		} else if strings.Contains(got[0].Detail, dir) {
			// The row names the file already; its detail does not repeat it.
			t.Errorf("%s: detail repeats the path: %q", c.name, got[0].Detail)
		}
	}

	// Two components importing one file are checked apart, as each holds it to its own repository.
	got := Run(context.Background(), []plugin.Target{
		plugin.FileTarget{Path: plain, Component: "api", Repositories: one, Commit: firstHead},
		plugin.FileTarget{Path: plain, Component: "web", Repositories: []plugin.RepositoryTarget{two[1]}, Commit: firstHead},
	}, Options{Probes: probes})
	if len(got) != 2 || got[0].Status != Passed || got[1].Status != Failed ||
		got[0].Target != plain+" · api" || got[1].Target != plain+" · web" {
		t.Errorf("one file, two components: %+v, want api passed and web failed, each row naming its component", got)
	}
}
