package publish

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// glEnv sets what a GitLab merge-request pipeline provides.
func glEnv(t *testing.T, apiURL string) {
	t.Helper()
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_API_V4_URL", apiURL)
	t.Setenv("CI_SERVER_URL", "")
	t.Setenv("CI_PROJECT_ID", "1234")
	t.Setenv("CI_MERGE_REQUEST_IID", "42")
	t.Setenv("GITLAB_TOKEN", "glpat-token")
}

func TestGitLabMRCommentCreatesANoteWhenNoneExists(t *testing.T) {
	var method, path, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		method, path = r.Method, r.URL.Path
		var b struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		body = b.Body
		_, _ = w.Write([]byte(`{"id":7}`))
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, err := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %s, want POST", method)
	}
	if want := "/projects/1234/merge_requests/42/notes"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if !strings.Contains(body, defaultPRMarker) {
		t.Errorf("the marker is what makes the next run an edit rather than a duplicate: %q", body)
	}
	if !strings.Contains(body, "Draugr diff") {
		t.Errorf("body = %q", body)
	}
}

func TestGitLabMRCommentEditsTheExistingNoteInPlace(t *testing.T) {
	var method, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[
				{"id":3,"system":false,"body":"a reviewer said something"},
				{"id":11,"system":false,"body":"` + defaultPRMarker + `\nold report"}
			]`))
			return
		}
		method, path = r.Method, r.URL.Path
		_, _ = w.Write([]byte(`{"id":11}`))
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut {
		t.Errorf("method = %s, want PUT — a second pipeline run must not add a second note", method)
	}
	if !strings.HasSuffix(path, "/notes/11") {
		t.Errorf("edited %q, want the marked note", path)
	}
}

func TestGitLabMRCommentIgnoresSystemNotes(t *testing.T) {
	// GitLab writes its own notes into the same list ("added 3 commits", "marked as draft"). One
	// carrying the marker is not Draugr's to edit, and a PUT against it fails or rewrites history
	// somebody else owns.
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{"id":9,"system":true,"body":"quoting ` + defaultPRMarker + ` here"}]`))
			return
		}
		method = r.Method
		_, _ = w.Write([]byte(`{"id":12}`))
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %s, want POST — a system note is not Draugr's own comment", method)
	}
}

func TestGitLabMRCommentFollowsPagination(t *testing.T) {
	// GitLab answers 20 notes at a time. Reading only the first page finds nothing as soon as a
	// merge request has a normal amount of discussion, and the publisher posts a fresh report every
	// run — the sticky comment failing by multiplying, exactly where the thread is long enough to
	// need it.
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
		if page == "1" {
			w.Header().Set("x-next-page", "2")
			_, _ = w.Write([]byte(`[{"id":3,"system":false,"body":"chatter"}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":11,"system":false,"body":"` + defaultPRMarker + `\nold report"}]`))
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if len(pages) != 2 || pages[0] != "1" || pages[1] != "2" {
		t.Errorf("requested pages %v, want the second page to be read too", pages)
	}
	if method != http.MethodPut || !strings.HasSuffix(path, "/notes/11") {
		t.Errorf("%s %q, want a PUT to the note found on page two", method, path)
	}
}

func TestGitLabMRCommentStopsPagingAtTheLastPage(t *testing.T) {
	// The absence of x-next-page is what ends the loop. A publisher that kept asking would spin
	// against a real instance rather than post anything.
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
			_, _ = w.Write([]byte(`[{"id":3,"system":false,"body":"chatter"}]`))
			return
		}
		_, _ = w.Write([]byte(`{"id":12}`))
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if gets != 1 {
		t.Errorf("listed %d pages, want 1 — no x-next-page means there is no next page", gets)
	}
}

func TestGitLabMRCommentSendsThePrivateTokenHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("PRIVATE-TOKEN")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	_ = p.Publish(context.Background(), []report.Artifact{mdArtifact()})
	if got != "glpat-token" {
		t.Errorf("PRIVATE-TOKEN = %q — GitLab authenticates access tokens with this header", got)
	}
}

func TestGitLabMRCommentExplicitConfigBeatsTheEnvironment(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// EscapedPath, not Path: the point is what went on the wire. Path is already decoded, so
		// asserting on it would pass whether or not the slashes were escaped.
		path = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, err := For(saga.PublisherConfig{
		Kind: "gitlab-mr-comment", Repo: "group/sub/project", PR: 99,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Publish(context.Background(), []report.Artifact{mdArtifact()})
	// A project inside a group is addressed by its full path, and every slash in it has to reach
	// GitLab as %2F or the request names something else — a 404 that reads like a missing project.
	want := "/projects/group%2Fsub%2Fproject/merge_requests/99/notes"
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestGitLabAPIURLFallsBackToTheServerURL(t *testing.T) {
	// A self-managed instance always sets CI_API_V4_URL, but a descriptor run outside a pipeline
	// against one has only the server URL to go on, and defaulting to gitlab.com there would send
	// somebody's report to the wrong host.
	cases := []struct{ name, api, server, want string }{
		{"api url wins", "https://git.example.com/api/v4", "https://git.example.com", "https://git.example.com/api/v4"},
		{"trailing slash trimmed", "https://git.example.com/api/v4/", "", "https://git.example.com/api/v4"},
		{"server url derives it", "", "https://git.example.com/", "https://git.example.com/api/v4"},
		{"neither means gitlab.com", "", "", "https://gitlab.com/api/v4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CI_API_V4_URL", tc.api)
			t.Setenv("CI_SERVER_URL", tc.server)
			if got := gitlabAPIURL(); got != tc.want {
				t.Errorf("gitlabAPIURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGitLabMRCommentNamesTheJobTokenTrap(t *testing.T) {
	// CI_JOB_TOKEN is in every GitLab job and is read-only on the notes API, so it is both the
	// obvious thing to reach for and the one that cannot work. An error that only says "missing
	// token" sends someone to the variable they already have.
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_ID", "1234")
	t.Setenv("CI_MERGE_REQUEST_IID", "42")
	t.Setenv("GITLAB_TOKEN", "")

	_, err := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "CI_JOB_TOKEN") || !strings.Contains(err.Error(), "api") {
		t.Errorf("the error should name the fix: %v", err)
	}
}

func TestGitLabMRCommentNamesAMissingProject(t *testing.T) {
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_ID", "")
	t.Setenv("CI_MERGE_REQUEST_IID", "42")
	t.Setenv("GITLAB_TOKEN", "glpat-token")

	_, err := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err == nil || !strings.Contains(err.Error(), "CI_PROJECT_ID") {
		t.Errorf("the error should name the variable: %v", err)
	}
}

func TestGitLabMRCommentNoopWithoutAMergeRequest(t *testing.T) {
	// A branch pipeline carrying the same Saga must not fail, or a project needs two descriptors.
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_MERGE_REQUEST_IID", "")
	p, err := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), nil); err != nil {
		t.Errorf("a no-op publisher returned an error: %v", err)
	}
	if p.Kind() != "gitlab-mr-comment" {
		t.Errorf("Kind() = %q", p.Kind())
	}
}

func TestGitLabMRCommentNoopOutsideGitLab(t *testing.T) {
	// Same Saga on a laptop.
	t.Setenv("GITLAB_CI", "")
	t.Setenv("CI_MERGE_REQUEST_IID", "")
	p, err := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), nil); err != nil {
		t.Errorf("a no-op publisher returned an error: %v", err)
	}
}

func TestGitLabMRCommentKindIsItsConfigSelector(t *testing.T) {
	glEnv(t, "https://gitlab.com/api/v4")
	p, err := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind() != "gitlab-mr-comment" {
		t.Errorf("Kind() = %q", p.Kind())
	}
}

func TestGitLabMRCommentRequiresMarkdown(t *testing.T) {
	glEnv(t, "https://gitlab.com/api/v4")
	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	err := p.Publish(context.Background(), []report.Artifact{{Format: "sarif", Bytes: []byte("{}")}})
	if err == nil || !strings.Contains(err.Error(), "markdown") {
		t.Errorf("a merge request comment has nothing to say without a markdown report: %v", err)
	}
}

func TestGitLabMRCommentSurfacesARefusalAsAPermission(t *testing.T) {
	// 401 and 403 both mean the request reached GitLab and the token was not enough — a token
	// problem, not a Saga problem. Saying so beats leaving someone re-reading their descriptor.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(`[]`))
					return
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"message":"403 Forbidden"}`))
			}))
			defer srv.Close()
			glEnv(t, srv.URL)

			p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
			err := p.Publish(context.Background(), []report.Artifact{mdArtifact()})
			if err == nil || !strings.Contains(err.Error(), "api") {
				t.Errorf("the error should name the scope and the role: %v", err)
			}
		})
	}
}

func TestGitLabMRCommentSurfacesAWriteFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"boom"}`))
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err == nil {
		t.Error("a failed write was swallowed, which reports success with no comment posted")
	}
}

func TestGitLabMRCommentSurfacesAListFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err == nil {
		t.Error("a failed lookup was swallowed, which would post a duplicate every run")
	}
}

func TestGitLabMRCommentSurfacesAnUnreadableListing(t *testing.T) {
	// A proxy or a login page answering 200 with HTML is the realistic version of this. Treating an
	// undecodable listing as "no existing note" would post a duplicate every run and never say why.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>sign in</html>`))
	}))
	defer srv.Close()
	glEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err == nil {
		t.Error("an undecodable note listing was treated as an empty one")
	}
}

func TestGitLabMRCommentSurfacesATransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // nothing is listening
	glEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "gitlab-mr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err == nil {
		t.Error("an unreachable instance was reported as a successful publish")
	}
}
