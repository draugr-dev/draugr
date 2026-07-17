package publish

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// ghEnv points the github publisher at a test server and sets the standard CI env.
func ghEnv(t *testing.T, apiURL string) {
	t.Helper()
	t.Setenv("GITHUB_API_URL", apiURL)
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_SHA", "deadbeef")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_TOKEN", "secret-token")
}

func TestGithubPublisherUploadsSARIF(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	ghEnv(t, srv.URL)

	p, err := For(saga.PublisherConfig{Kind: "github"})
	if err != nil {
		t.Fatal(err)
	}
	sarif, _ := report.Build(saga.ReportConfig{Format: "sarif"}, sampleData())
	if err := p.Publish(context.Background(), []report.Artifact{sarif}); err != nil {
		t.Fatal(err)
	}

	if gotAuth != "Bearer secret-token" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if gotPath != "/repos/acme/app/code-scanning/sarifs" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody["commit_sha"] != "deadbeef" || gotBody["ref"] != "refs/heads/main" {
		t.Errorf("body meta = %+v", gotBody)
	}
	// The sarif field must be gzip+base64 of the report.
	raw, err := base64.StdEncoding.DecodeString(gotBody["sarif"])
	if err != nil {
		t.Fatalf("sarif not base64: %v", err)
	}
	zr, err := gzip.NewReader(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("sarif not gzip: %v", err)
	}
	decoded, _ := io.ReadAll(zr)
	if !strings.Contains(string(decoded), "runs") {
		t.Errorf("decoded sarif missing content: %s", decoded)
	}
}

func TestGithubPublisherConfigOverridesEnv(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("MY_TOKEN", "custom-token")

	p, err := For(saga.PublisherConfig{
		Kind: "github", Repo: "org/repo", Commit: "abc", Ref: "refs/heads/dev", TokenEnv: "MY_TOKEN",
	})
	if err != nil {
		t.Fatal(err)
	}
	sarif, _ := report.Build(saga.ReportConfig{Format: "sarif"}, sampleData())
	if err := p.Publish(context.Background(), []report.Artifact{sarif}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/repos/org/repo/code-scanning/sarifs" || gotAuth != "Bearer custom-token" {
		t.Errorf("path=%q auth=%q", gotPath, gotAuth)
	}
}

func TestGithubPublisherMissingConfig(t *testing.T) {
	// No env, no config → all required fields missing.
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_REF", "")
	t.Setenv("GITHUB_TOKEN", "")
	_, err := For(saga.PublisherConfig{Kind: "github"})
	if err == nil {
		t.Fatal("expected error for missing github config")
	}
	for _, want := range []string{"repo", "commit", "ref", "GITHUB_TOKEN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

func TestGithubPublisherRequiresSARIF(t *testing.T) {
	ghEnv(t, "https://example.invalid")
	p, err := For(saga.PublisherConfig{Kind: "github"})
	if err != nil {
		t.Fatal(err)
	}
	md, _ := report.Build(saga.ReportConfig{Format: "markdown"}, sampleData())
	if err := p.Publish(context.Background(), []report.Artifact{md}); err == nil ||
		!strings.Contains(err.Error(), "requires a 'sarif' report") {
		t.Fatalf("expected sarif-required error, got %v", err)
	}
}

func TestPublisherKinds(t *testing.T) {
	f, _ := For(saga.PublisherConfig{Kind: "file", Dir: "x"})
	if f.Kind() != "file" {
		t.Errorf("file kind = %q", f.Kind())
	}
	ghEnv(t, "https://example.invalid")
	g, _ := For(saga.PublisherConfig{Kind: "github"})
	if g.Kind() != "github" {
		t.Errorf("github kind = %q", g.Kind())
	}
}

func TestGithubPublisherTransportError(t *testing.T) {
	// A closed server address makes the HTTP request itself fail.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now nothing is listening
	ghEnv(t, url)

	p, _ := For(saga.PublisherConfig{Kind: "github"})
	sarif, _ := report.Build(saga.ReportConfig{Format: "sarif"}, sampleData())
	if err := p.Publish(context.Background(), []report.Artifact{sarif}); err == nil {
		t.Error("expected a transport error when the server is unreachable")
	}
}

func TestGithubPublisherServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible"}`))
	}))
	defer srv.Close()
	ghEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "github"})
	sarif, _ := report.Build(saga.ReportConfig{Format: "sarif"}, sampleData())
	err := p.Publish(context.Background(), []report.Artifact{sarif})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected a 403 error, got %v", err)
	}
}
