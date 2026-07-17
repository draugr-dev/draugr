package publish

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func prEnv(t *testing.T, apiURL string) {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_API_URL", apiURL)
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")
	t.Setenv("GITHUB_TOKEN", "secret")
}

func mdArtifact() report.Artifact {
	return report.Artifact{Format: "markdown", Bytes: []byte("## Draugr diff\n\n2 new, 3 fixed")}
}

func TestPRCommentCreatesWhenNoneExists(t *testing.T) {
	var method, path, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`[]`)) // no existing comments
		default:
			method, path = r.Method, r.URL.Path
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			gotBody = b["body"]
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	prEnv(t, srv.URL)

	p, err := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || path != "/repos/acme/app/issues/42/comments" {
		t.Errorf("create: method=%s path=%s", method, path)
	}
	if !strings.Contains(gotBody, defaultPRMarker) || !strings.Contains(gotBody, "Draugr diff") {
		t.Errorf("body missing marker or content: %q", gotBody)
	}
}

func TestPRCommentUpdatesExisting(t *testing.T) {
	var method, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{"id":999,"body":"` + defaultPRMarker + `\nold"}]`))
			return
		}
		method, path = r.Method, r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	prEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPatch || path != "/repos/acme/app/issues/comments/999" {
		t.Errorf("update: method=%s path=%s", method, path)
	}
}

func TestPRCommentParsesPRFromRef(t *testing.T) {
	prEnv(t, "https://example.invalid")
	t.Setenv("GITHUB_REF", "refs/pull/7/merge")
	p, err := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind() != "github-pr-comment" {
		t.Errorf("kind = %q", p.Kind())
	}
}

func TestPRCommentNoopWithoutPR(t *testing.T) {
	// A push build (branch ref, no PR) → no-op, not an error.
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_TOKEN", "secret")
	p, err := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Errorf("no-op publish should succeed, got %v", err)
	}
}

func TestPRCommentNoopOutsideCI(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITHUB_REF", "")
	p, err := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), nil); err != nil {
		t.Errorf("no-op publish should succeed, got %v", err)
	}
}

func TestPRCommentRequiresMarkdown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	prEnv(t, srv.URL)
	p, _ := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	sarif, _ := report.Build(saga.ReportConfig{Format: "sarif"}, sampleData())
	if err := p.Publish(context.Background(), []report.Artifact{sarif}); err == nil ||
		!strings.Contains(err.Error(), "requires a 'markdown' report") {
		t.Fatalf("expected markdown-required error, got %v", err)
	}
}

func TestPRCommentListError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // GET list fails
	}))
	defer srv.Close()
	prEnv(t, srv.URL)
	p, _ := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err == nil ||
		!strings.Contains(err.Error(), "list PR comments failed") {
		t.Fatalf("expected list error, got %v", err)
	}
}

func TestPRCommentPostError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(http.StatusUnprocessableEntity) // POST fails
	}))
	defer srv.Close()
	prEnv(t, srv.URL)
	p, _ := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err == nil ||
		!strings.Contains(err.Error(), "post PR comment failed") {
		t.Fatalf("expected post error, got %v", err)
	}
}

func TestPRCommentMissingTokenErrors(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")
	t.Setenv("GITHUB_TOKEN", "")
	if _, err := For(saga.PublisherConfig{Kind: "github-pr-comment"}); err == nil ||
		!strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("expected missing-token error, got %v", err)
	}
}
