//go:build integration

package integration

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a throwaway endpoint that remembers how it was reached.
type recorder struct {
	mu      sync.Mutex
	methods map[string]int
	authed  int
	anon    int
	url     string
	stop    func()
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{methods: map[string]int{}}
	srv := &http.Server{
		// A timeout even here: the fixture is short-lived and local, but a server without one is
		// the finding this project would report on somebody else's code.
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			r.mu.Lock()
			r.methods[req.Method]++
			if req.Header.Get("Authorization") != "" {
				r.authed++
			} else {
				r.anon++
			}
			r.mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>ok</body></html>"))
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	r.url = "http://" + ln.Addr().String()
	r.stop = func() { _ = srv.Close() }
	t.Cleanup(r.stop)
	return r
}

func (r *recorder) seen() (map[string]int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int, len(r.methods))
	for k, v := range r.methods {
		out[k] = v
	}
	return out, r.authed, r.anon
}

func (r *recorder) summary() string {
	methods, authed, anon := r.seen()
	keys := make([]string, 0, len(methods))
	for k := range methods {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, methods[k]))
	}
	return fmt.Sprintf("%s (authenticated=%d anonymous=%d)", strings.Join(parts, " "), authed, anon)
}

// runDast scans a descriptor and returns the combined output. A non-zero exit is not a failure
// here: whether findings trip the gate is the Norn's business, not this test's.
func runDast(t *testing.T, dir, saga string, env ...string) string {
	t.Helper()
	// #nosec G204 -- the binary under test, against a descriptor this test wrote into t.TempDir().
	cmd := exec.Command(draugrBin(t), "scan", saga, "--log-level", "warn")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	t.Logf("draugr scan %s exit=%v\n%s", saga, err, out)
	return string(out)
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const dastSpec = `openapi: 3.0.0
info: { title: demo, version: "1.0" }
servers:
  - url: https://api.production.invalid
paths:
  /widgets:
    get: { responses: { "200": { description: ok } } }
    post: { responses: { "201": { description: made } } }
  /widgets/{id}:
    parameters:
      - { name: id, in: path, required: true, schema: { type: string, example: abc } }
    get: { responses: { "200": { description: ok } } }
    delete: { responses: { "204": { description: gone } } }
`

func dastSaga(url, extra string) string {
	return fmt.Sprintf(`release: { name: dast-integration, version: "1.0" }
config:
  controllers:
    dast: { enabled: true }
components:
  - name: api
    exposure:
      value: public
    criticality:
      value: critical
    hosts:
      - name: api
        url: %s
        type: api
%s`, url, extra)
}

// TestDastSpecScanStaysWhereItWasPointed is the assertion the spec feature exists for.
//
// A scanner handed an OpenAPI document takes its targets from that document. This specification
// names api.production.invalid, and the descriptor names a local endpoint — so if the rewrite ever
// stopped pinning `servers:`, the scan would leave for somewhere nobody authorized, and every unit
// test would still pass.
//
// The domain is `.invalid` deliberately: reserved by RFC 2606 and unresolvable, so a regression
// fails this test rather than sending probe traffic somewhere real.
func TestDastSpecScanStaysWhereItWasPointed(t *testing.T) {
	requireTool(t, "nuclei", "this test is the real scanner being driven from a specification")

	rec := newRecorder(t)
	dir := t.TempDir()
	writeFile(t, dir, "openapi.yaml", dastSpec)
	writeFile(t, dir, "draugr.saga.yaml", dastSaga(rec.url, "        spec:\n          path: openapi.yaml\n"))

	runDast(t, dir, "draugr.saga.yaml")

	methods, _, _ := rec.seen()
	if methods["GET"] == 0 {
		t.Fatalf("the scan never reached the declared endpoint: %s", rec.summary())
	}
	// Read-only by default. A specification lists POST and DELETE too, and a scanner handed the
	// unfiltered document will use them.
	for _, write := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if methods[write] > 0 {
			t.Errorf("a read-only scan sent %d %s requests: %s", methods[write], write, rec.summary())
		}
	}
}

// TestDastSpecScanSendsOnlyTheMethodsNamed checks that naming a write method enables exactly that
// one — the whole basis for treating the descriptor as the consent.
func TestDastSpecScanSendsOnlyTheMethodsNamed(t *testing.T) {
	requireTool(t, "nuclei", "this test is the real scanner being driven from a specification")

	rec := newRecorder(t)
	dir := t.TempDir()
	writeFile(t, dir, "openapi.yaml", dastSpec)
	writeFile(t, dir, "draugr.saga.yaml",
		dastSaga(rec.url, "        spec:\n          path: openapi.yaml\n          methods: [get, post]\n"))

	out := runDast(t, dir, "draugr.saga.yaml")

	methods, _, _ := rec.seen()
	if methods["POST"] == 0 {
		t.Errorf("post was named and never sent: %s", rec.summary())
	}
	if methods["DELETE"] > 0 {
		t.Errorf("delete was not named and was sent %d times: %s", methods["DELETE"], rec.summary())
	}
	// Excluding an operation silently would leave a partial scan reading like a complete one.
	if !strings.Contains(out, "delete") {
		t.Errorf("the run never said the delete operation was excluded:\n%s", out)
	}
}

// TestDastAuthenticatedScanSendsTheCredential covers the other half: a scan that authenticates
// reaches the application, and one that cannot authenticate refuses rather than quietly probing
// the login page and reporting a pass.
func TestDastAuthenticatedScanSendsTheCredential(t *testing.T) {
	requireTool(t, "nuclei", "this test is the real scanner carrying a credential")

	rec := newRecorder(t)
	dir := t.TempDir()
	writeFile(t, dir, "openapi.yaml", dastSpec)
	// Driven from the specification, which is both the realistic pairing for an API and what keeps
	// this test to seconds: pointed at a bare URL, Nuclei runs its whole template set and the same
	// assertion costs five minutes of a fifteen-minute budget shared with the cluster tests.
	writeFile(t, dir, "draugr.saga.yaml", dastSaga(rec.url,
		"        spec:\n          path: openapi.yaml\n"+
			"        auth:\n          type: bearer\n          tokenEnv: DRAUGR_IT_TOKEN\n"))

	runDast(t, dir, "draugr.saga.yaml", "DRAUGR_IT_TOKEN=integration-token")

	_, authed, _ := rec.seen()
	if authed == 0 {
		t.Fatalf("no request carried the credential: %s", rec.summary())
	}

	// And with the variable unset it must not fall back to an anonymous scan.
	quiet := newRecorder(t)
	dir2 := t.TempDir()
	writeFile(t, dir2, "draugr.saga.yaml",
		dastSaga(quiet.url, "        auth:\n          type: bearer\n          tokenEnv: DRAUGR_IT_ABSENT\n"))

	out := runDast(t, dir2, "draugr.saga.yaml", "DRAUGR_IT_ABSENT=")
	if !strings.Contains(out, "DRAUGR_IT_ABSENT") {
		t.Errorf("an unset credential should name the variable to set:\n%s", out)
	}
	if methods, _, _ := quiet.seen(); len(methods) > 0 {
		t.Errorf("the scan ran anyway, unauthenticated: %s", quiet.summary())
	}
}

// TestNativeHostControlsReachAnEndpoint covers headers and tls, which ship with no external tool
// and had no integration coverage at all. They need only an endpoint, and this one is local.
func TestNativeHostControlsReachAnEndpoint(t *testing.T) {
	rec := newRecorder(t)
	dir := t.TempDir()
	writeFile(t, dir, "draugr.saga.yaml", fmt.Sprintf(`release: { name: headers-integration, version: "1.0" }
config:
  controllers:
    headers: { enabled: true }
components:
  - name: api
    exposure:
      value: public
    criticality:
      value: critical
    hosts:
      - name: api
        url: %s
        type: api
`, rec.url))

	out := runDast(t, dir, "draugr.saga.yaml")

	if methods, _, _ := rec.seen(); methods["GET"] == 0 && methods["HEAD"] == 0 {
		t.Fatalf("the headers control never reached the endpoint: %s", rec.summary())
	}
	// The fixture sets no security headers at all, so the control has something to say. What it
	// must not do is pass in silence.
	if !strings.Contains(out, "headers") {
		t.Errorf("the report never mentions the headers control:\n%s", out)
	}
}
