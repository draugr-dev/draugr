package tools

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A tool Draugr provisions and cannot ask about is one nothing can notice has gone stale, which is
// the drift the checker exists to end. Held to the installable list rather than to memory.
func TestEveryProvisionedToolHasAnUpstream(t *testing.T) {
	for _, name := range Installable() {
		if _, ok := UpstreamFor(name); !ok {
			t.Errorf("%s is installable and names no upstream, so nothing can tell when it is "+
				"behind; add it to upstreams", name)
		}
	}
	// And the other way: an upstream for something nobody installs is a row that will never be
	// checked against anything.
	installable := map[string]bool{}
	for _, name := range Installable() {
		installable[name] = true
	}
	for name := range upstreams {
		if !installable[name] {
			t.Errorf("%s names an upstream and is not installable", name)
		}
	}
}

// Every pinned tool reports the version it installs, whichever way it is packaged. A tool whose
// pin reads empty compares equal to nothing and is reported current forever.
func TestEveryProvisionedToolReportsItsPinnedVersion(t *testing.T) {
	for _, name := range Installable() {
		if PinnedVersion(name) == "" {
			t.Errorf("%s reports no pinned version", name)
		}
	}
}

// The case that made a separate strategy necessary. A repository holding several modules marks as
// latest whichever release was published most recently, which for golang/vuln is not the newest
// govulncheck: the tags say v1.8.0 and the release says v1.1.4.
func TestTheNewestTagIsFoundWhateverOrderTheyArriveIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"name":"v1.1.4"},
			{"name":"internal/v0.9.0"},
			{"name":"v1.8.0"},
			{"name":"v1.7.0"},
			{"name":"v2.0.0-rc1"},
			{"name":"not-a-version"}
		]`))
	}))
	t.Cleanup(srv.Close)

	got, err := githubTagAt(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("githubTag: %v", err)
	}
	// v1.8.0 over v1.1.4 though the older is listed first, and neither the module-scoped tag nor
	// the release candidate: both are real tags and neither is what Draugr would install.
	if got != "1.8.0" {
		t.Errorf("newest tag = %q, want 1.8.0", got)
	}
}

// A listing larger than any upstream publishes is refused as what it is. Decoding a truncated body
// reports a JSON error, which reads as an upstream answering badly rather than as a limit of ours.
func TestAnOversizeListingIsRefusedAsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[" + strings.Repeat(`{"name":"v1.0.0"},`, 10)))
	}))
	t.Cleanup(srv.Close)

	prior := maxMetadataForTest
	maxMetadataForTest = 8
	t.Cleanup(func() { maxMetadataForTest = prior })

	_, err := githubTagAt(context.Background(), srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("err = %v, want the size refusal", err)
	}
}

// Being behind is a difference, never an ordering. A pin ahead of its upstream is a real state, a
// release withdrawn after Draugr pinned it, and somebody needs to see it rather than have it
// reported as current.
func TestBehindIsADifferenceAndNotAComparison(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    Drift
		want bool
	}{
		{"behind", Drift{Pinned: "1.0.0", Latest: "1.1.0"}, true},
		{"ahead of a withdrawn release", Drift{Pinned: "1.1.0", Latest: "1.0.0"}, true},
		{"current", Drift{Pinned: "1.0.0", Latest: "1.0.0"}, false},
		{"unanswered", Drift{Pinned: "1.0.0", Err: context.Canceled}, false},
		{"answered with nothing", Drift{Pinned: "1.0.0"}, false},
	} {
		if got := tc.d.Behind(); got != tc.want {
			t.Errorf("%s: Behind() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// upstreamTransport answers every request in-process, keyed by host and path, so the URLs the
// resolvers build are the ones under test rather than a URL a test passes in.
type upstreamTransport struct {
	routes map[string]func(w http.ResponseWriter, r *http.Request)
	seen   []*http.Request
}

func (u *upstreamTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	u.seen = append(u.seen, r)
	rec := httptest.NewRecorder()
	if h, ok := u.routes[r.URL.Host+r.URL.Path]; ok {
		h(rec, r)
	} else {
		rec.WriteHeader(http.StatusNotFound)
	}
	return rec.Result(), nil
}

func serveJSON(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }
}

// Each kind of upstream is read from the place that kind publishes to, and an upstream that
// answers with nothing usable is an error rather than a version.
func TestLatestReadsEachKindOfUpstream(t *testing.T) {
	tr := &upstreamTransport{routes: map[string]func(http.ResponseWriter, *http.Request){
		"api.github.com/repos/aquasecurity/trivy/releases/latest": serveJSON(`{"tag_name":"v0.80.1"}`),
		"api.github.com/repos/golang/vuln/tags":                   serveJSON(`[{"name":"v1.1.4"},{"name":"v1.9.0"},{"name":"v1.10.0-rc1"}]`),
		"pypi.org/pypi/semgrep/json":                              serveJSON(`{"info":{"version":"1.200.0"}}`),
		"registry.npmjs.org/retire":                               serveJSON(`{"dist-tags":{"latest":"5.8.0","next":"6.0.0-beta"}}`),
	}}
	client := &http.Client{Transport: tr}
	for tool, want := range map[string]string{
		"trivy": "0.80.1", "govulncheck": "1.9.0", "semgrep": "1.200.0", "retire": "5.8.0",
	} {
		got, err := Latest(context.Background(), client, tool)
		if err != nil || got != want {
			t.Errorf("Latest(%s) = %q, %v; want %q", tool, got, err, want)
		}
	}
	for _, r := range tr.seen {
		if r.Header.Get("User-Agent") != "draugr" || r.Header.Get("Accept") != "application/json" {
			t.Errorf("%s sent without the headers: %v", r.URL, r.Header)
		}
	}
}

func TestLatestRefusesAnEmptyAnswer(t *testing.T) {
	client := &http.Client{Transport: &upstreamTransport{routes: map[string]func(http.ResponseWriter, *http.Request){
		"api.github.com/repos/aquasecurity/trivy/releases/latest": serveJSON(`{}`),
		"api.github.com/repos/golang/vuln/tags":                   serveJSON(`[{"name":"cmd/v1.0.0"},{"name":"v2"}]`),
		"pypi.org/pypi/semgrep/json":                              serveJSON(`{"info":{}}`),
		"registry.npmjs.org/retire":                               serveJSON(`{"dist-tags":{"next":"6.0.0"}}`),
	}}}
	for tool, want := range map[string]string{
		"trivy":       "aquasecurity/trivy names no latest release",
		"govulncheck": "publishes no vX.Y.Z tag",
		"semgrep":     "pypi names no current version for semgrep",
		"retire":      "npm names no latest version for retire",
	} {
		_, err := Latest(context.Background(), client, tool)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Latest(%s) error = %v, want %q", tool, err, want)
		}
	}
	if _, err := Latest(context.Background(), client, "kubectl"); err == nil ||
		!strings.Contains(err.Error(), "no upstream is recorded") {
		t.Errorf("a tool with no upstream: %v", err)
	}
}

// A rate limit and a refusal both answer 403, and need different things from the reader.
func TestARateLimitIsToldApartFromARefusal(t *testing.T) {
	client := &http.Client{Transport: &upstreamTransport{routes: map[string]func(http.ResponseWriter, *http.Request){
		"api.github.com/repos/aquasecurity/trivy/releases/latest": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
		},
		"api.github.com/repos/sigstore/cosign/releases/latest": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		},
	}}}
	_, err := Latest(context.Background(), client, "trivy")
	if err == nil || err.Error() != "api.github.com rate-limited this machine; it resets shortly, or set GITHUB_TOKEN to raise the limit" {
		t.Errorf("rate limit: %v", err)
	}
	_, err = Latest(context.Background(), client, "cosign")
	if err == nil || !strings.Contains(err.Error(), "answered 403 Forbidden") {
		t.Errorf("refusal: %v", err)
	}
}

// The token goes to GitHub and to nobody else.
func TestTheGitHubTokenIsSentOnlyToGitHub(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "test-token")
	tr := &upstreamTransport{routes: map[string]func(http.ResponseWriter, *http.Request){
		"api.github.com/repos/aquasecurity/trivy/releases/latest": serveJSON(`{"tag_name":"v1.0.0"}`),
		"pypi.org/pypi/semgrep/json":                              serveJSON(`{"info":{"version":"1.0.0"}}`),
	}}
	client := &http.Client{Transport: tr}
	_, _ = Latest(context.Background(), client, "trivy")
	_, _ = Latest(context.Background(), client, "semgrep")
	for _, r := range tr.seen {
		auth := r.Header.Get("Authorization")
		if r.URL.Host == "api.github.com" && auth != "Bearer test-token" {
			t.Errorf("GitHub request without the token: %q", auth)
		}
		if r.URL.Host != "api.github.com" && auth != "" {
			t.Errorf("token sent to %s", r.URL.Host)
		}
	}
}

// Every tool gets a row, the ones that could not be reached included.
func TestOutdatedReportsEveryToolInNameOrder(t *testing.T) {
	trivyPin := PinnedVersion("trivy")
	client := &http.Client{Transport: &upstreamTransport{routes: map[string]func(http.ResponseWriter, *http.Request){
		"api.github.com/repos/aquasecurity/trivy/releases/latest": serveJSON(`{"tag_name":"v` + trivyPin + `"}`),
		"api.github.com/repos/anchore/grype/releases/latest":      serveJSON(`{"tag_name":"v999.0.0"}`),
	}}}
	drift := Outdated(context.Background(), client)
	if len(drift) != len(upstreams) {
		t.Fatalf("%d rows for %d tools", len(drift), len(upstreams))
	}
	byTool := map[string]Drift{}
	for i, d := range drift {
		if i > 0 && drift[i-1].Tool >= d.Tool {
			t.Errorf("not in name order: %s before %s", drift[i-1].Tool, d.Tool)
		}
		byTool[d.Tool] = d
	}
	if d := byTool["trivy"]; d.Behind() || d.Err != nil || d.Pinned != trivyPin {
		t.Errorf("trivy at its pin: %+v", d)
	}
	if d := byTool["grype"]; !d.Behind() || d.Latest != "999.0.0" {
		t.Errorf("grype behind: %+v", d)
	}
	if d := byTool["syft"]; d.Err == nil || d.Behind() {
		t.Errorf("an unreachable upstream reads as current: %+v", d)
	}
}

func TestHostOf(t *testing.T) {
	for url, want := range map[string]string{
		"https://api.github.com/repos/x": "api.github.com",
		"http://example.test":            "example.test",
	} {
		if got := hostOf(url); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", url, got, want)
		}
	}
}
