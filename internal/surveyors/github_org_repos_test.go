package surveyors

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestGitHubOrgReposInfo(t *testing.T) {
	if NewGitHubOrgRepos().Info().Name != "github-org-repos" {
		t.Error("wrong name")
	}
}

func TestGitHubOrgReposRequiresOrg(t *testing.T) {
	_, err := NewGitHubOrgRepos().Survey(context.Background(), plugin.SurveyScope{})
	if err == nil {
		t.Fatal("expected error when org is missing")
	}
}

func TestGitHubOrgReposSurvey(t *testing.T) {
	var gotAuth string
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if page == 0 {
			page++
			// Signal a second page via Link header.
			w.Header().Set("Link", fmt.Sprintf(`<%s/next>; rel="next"`, srvURL(r)))
			_, _ = fmt.Fprint(w, `[{"name":"a","clone_url":"https://git/a.git","default_branch":"main"}]`)
			return
		}
		_, _ = fmt.Fprint(w, `[{"name":"b","clone_url":"https://git/b.git","default_branch":"dev"}]`)
	}))
	defer srv.Close()

	g := GitHubOrgRepos{baseURL: srv.URL, httpClient: srv.Client()}
	frag, err := g.Survey(context.Background(), plugin.SurveyScope{Ref: "acme", Config: plugin.Config{"token": "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.Components) != 2 {
		t.Fatalf("want 2 repos across pages, got %d", len(frag.Components))
	}
	if frag.Components[0].Repositories[0].URL != "https://git/a.git" {
		t.Errorf("repo url = %q", frag.Components[0].Repositories[0].URL)
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("auth header = %q, want Bearer secret", gotAuth)
	}
}

func TestGitHubOrgReposHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	g := GitHubOrgRepos{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := g.Survey(context.Background(), plugin.SurveyScope{Ref: "acme"}); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestNextLink(t *testing.T) {
	h := `<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"`
	if got := nextLink(h); got != "https://api.github.com/x?page=2" {
		t.Errorf("nextLink = %q", got)
	}
	if got := nextLink(`<https://x>; rel="last"`); got != "" {
		t.Errorf("no next should be empty, got %q", got)
	}
}

// srvURL reconstructs the server base URL from a request, so the next-page Link points
// back at the test server.
func srvURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
