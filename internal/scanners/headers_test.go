package scanners

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestHTTPFetchHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h, err := httpFetchHeaders(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("httpFetchHeaders: %v", err)
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("did not read response headers: %v", h)
	}

	// Unreachable server → error.
	srv.Close()
	if _, err := httpFetchHeaders(context.Background(), srv.URL); err == nil {
		t.Error("expected an error against a closed server")
	}
	// Malformed request URL → error.
	if _, err := httpFetchHeaders(context.Background(), "://bad-url"); err == nil {
		t.Error("expected an error for a malformed URL")
	}
}

func TestHTTPHeadersInfo(t *testing.T) {
	info := NewHTTPHeaders().Info()
	if info.Name != "http-headers" {
		t.Errorf("name = %q", info.Name)
	}
	if info.Binary != "" {
		t.Errorf("native scanner should have no Binary, got %q", info.Binary)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "headers" {
		t.Errorf("controls = %v", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetHost {
		t.Errorf("targetKinds = %v", info.TargetKinds)
	}
}

// ruleIDs collects the rule ids from a report for easy assertions.
func ruleIDs(rep sarif.Report) map[string]sarif.Level {
	out := make(map[string]sarif.Level, len(rep.Results))
	for _, r := range rep.Results {
		out[r.RuleID] = r.Level
	}
	return out
}

func scanWith(t *testing.T, host plugin.HostTarget, header http.Header) sarif.Report {
	t.Helper()
	s := httpHeadersScanner{
		info:  NewHTTPHeaders().Info(),
		fetch: func(context.Context, string) (http.Header, error) { return header, nil },
	}
	rep, err := s.Scan(context.Background(), host, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return rep
}

func TestHeadersBrowserMissingAll(t *testing.T) {
	rep := scanWith(t, plugin.HostTarget{URL: "https://app.example.com", Type: "browser"}, http.Header{})
	got := ruleIDs(rep)
	for id, want := range map[string]sarif.Level{
		"headers/hsts-missing":                   sarif.LevelWarning,
		"headers/x-content-type-options-missing": sarif.LevelWarning,
		"headers/csp-missing":                    sarif.LevelWarning,
		"headers/x-frame-options-missing":        sarif.LevelWarning,
		"headers/referrer-policy-missing":        sarif.LevelNote,
		"headers/permissions-policy-missing":     sarif.LevelNote,
	} {
		if got[id] != want {
			t.Errorf("browser: %s = %q, want %q", id, got[id], want)
		}
	}
	// Location should be the URL.
	if rep.Results[0].Location.URI != "https://app.example.com" {
		t.Errorf("location = %q", rep.Results[0].Location.URI)
	}
}

func TestHeadersAPISkipsBrowserOnly(t *testing.T) {
	rep := scanWith(t, plugin.HostTarget{URL: "https://api.example.com", Type: "api"}, http.Header{})
	got := ruleIDs(rep)
	for _, browserOnly := range []string{
		"headers/csp-missing", "headers/x-frame-options-missing",
		"headers/referrer-policy-missing", "headers/permissions-policy-missing",
	} {
		if _, present := got[browserOnly]; present {
			t.Errorf("api host should not flag browser-only rule %s", browserOnly)
		}
	}
	// but universal rules still apply
	if _, ok := got["headers/hsts-missing"]; !ok {
		t.Error("api host should still flag missing HSTS")
	}
	if _, ok := got["headers/cache-control-missing"]; !ok {
		t.Error("api host should flag missing Cache-Control")
	}
}

func TestHeadersDefaultTypeIsBrowser(t *testing.T) {
	// Empty type behaves like browser (full suite).
	rep := scanWith(t, plugin.HostTarget{URL: "https://x", Type: ""}, http.Header{})
	if _, ok := ruleIDs(rep)["headers/csp-missing"]; !ok {
		t.Error("empty type should default to browser (CSP checked)")
	}
}

func TestHeadersWellConfiguredBrowserIsClean(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "geolocation=()")
	// X-Frame-Options covered by CSP frame-ancestors.
	rep := scanWith(t, plugin.HostTarget{URL: "https://app", Type: "browser"}, h)
	if len(rep.Results) != 0 {
		t.Errorf("well-configured host should have no findings, got %+v", rep.Results)
	}
}

func TestHeadersValueChecks(t *testing.T) {
	// X-Content-Type-Options present but wrong.
	h := http.Header{}
	h.Set("X-Content-Type-Options", "sniff")
	h.Set("Server", "nginx/1.2.3")
	h.Set("X-Powered-By", "Express")
	rep := scanWith(t, plugin.HostTarget{URL: "https://x", Type: "api"}, h)
	got := ruleIDs(rep)
	if got["headers/x-content-type-options-invalid"] != sarif.LevelWarning {
		t.Error("wrong X-Content-Type-Options value should be flagged")
	}
	if got["headers/server-disclosure"] != sarif.LevelNote || got["headers/x-powered-by-disclosure"] != sarif.LevelNote {
		t.Error("disclosure headers should be flagged as notes")
	}
}

func TestHeadersCORSWildcard(t *testing.T) {
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Cache-Control", "no-store")
	rep := scanWith(t, plugin.HostTarget{URL: "https://api", Type: "api"}, h)
	if ruleIDs(rep)["headers/cors-wildcard"] != sarif.LevelWarning {
		t.Error("wildcard CORS should be a warning")
	}

	h.Set("Access-Control-Allow-Credentials", "true")
	rep = scanWith(t, plugin.HostTarget{URL: "https://api", Type: "api"}, h)
	if ruleIDs(rep)["headers/cors-wildcard-with-credentials"] != sarif.LevelError {
		t.Error("wildcard CORS with credentials should be an error")
	}
}

func TestHeadersHSTSOnlyHTTPS(t *testing.T) {
	// Plain http → HSTS not flagged (it only applies to https).
	rep := scanWith(t, plugin.HostTarget{URL: "http://x", Type: "api"}, http.Header{})
	if _, ok := ruleIDs(rep)["headers/hsts-missing"]; ok {
		t.Error("HSTS should not be flagged for http URLs")
	}
}

func TestHeadersScanErrors(t *testing.T) {
	s := NewHTTPHeaders()
	// Wrong target type.
	if _, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: "x"}, nil); err == nil {
		t.Error("expected error for non-host target")
	}
	// Empty URL.
	if _, err := s.Scan(context.Background(), plugin.HostTarget{}, nil); err == nil {
		t.Error("expected error for empty URL")
	}
	// Fetch failure.
	failing := httpHeadersScanner{
		info:  s.Info(),
		fetch: func(context.Context, string) (http.Header, error) { return nil, errors.New("boom") },
	}
	if _, err := failing.Scan(context.Background(), plugin.HostTarget{URL: "https://x"}, nil); err == nil {
		t.Error("expected error when fetch fails")
	}
}
