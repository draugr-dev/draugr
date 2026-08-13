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

// A hundred comments is a page, and a pull request that has had a real conversation passes that.
//
// Reading one page then finds no marker, and the publisher posts a fresh report every run — the
// sticky comment stops being sticky exactly where a long thread makes it worth having, and it
// degrades by adding noise rather than by failing.
func TestPRCommentFollowsPagination(t *testing.T) {
	var pages []string
	var method, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			method, path = r.Method, r.URL.Path
			_, _ = w.Write([]byte(`{"id":11}`))
			return
		}
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		if page == "" || page == "1" {
			// GitHub gives the whole next URL rather than a page number, cursor included.
			w.Header().Set("Link", `<http://`+r.Host+r.URL.Path+`?per_page=100&page=2>; rel="next"`)
			_, _ = w.Write([]byte(`[{"id":3,"body":"a reviewer said something"}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":11,"body":"` + defaultPRMarker + `\nold report"}]`))
	}))
	defer srv.Close()
	prEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if len(pages) != 2 {
		t.Errorf("read %d page(s) %v, want the second one to be read too", len(pages), pages)
	}
	if method != http.MethodPatch || !strings.HasSuffix(path, "/comments/11") {
		t.Errorf("%s %q, want a PATCH to the comment found on page two", method, path)
	}
}

// The absence of a rel="next" link is what ends the loop. A publisher that kept asking would spin
// against a real repository rather than post anything.
func TestPRCommentStopsAtTheLastPage(t *testing.T) {
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
			// A Link header that offers only a previous page must not be followed.
			w.Header().Set("Link", `<https://api.github.com/x?page=1>; rel="prev"`)
			_, _ = w.Write([]byte(`[{"id":3,"body":"chatter"}]`))
			return
		}
		_, _ = w.Write([]byte(`{"id":12}`))
	}))
	defer srv.Close()
	prEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "github-pr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if gets != 1 {
		t.Errorf("listed %d pages, want 1 — only rel=\"next\" is a next page", gets)
	}
}

func TestNextPageURL(t *testing.T) {
	cases := map[string]string{
		`<https://api.github.com/x?page=2>; rel="next"`:                                 "https://api.github.com/x?page=2",
		`<https://api.github.com/x?page=1>; rel="prev", <https://y?page=3>; rel="next"`: "https://y?page=3",
		`<https://api.github.com/x?page=9>; rel="last"`:                                 "",
		``: "",
	}
	for header, want := range cases {
		if got := nextPageURL(header); got != want {
			t.Errorf("nextPageURL(%q) = %q, want %q", header, got, want)
		}
	}
}
