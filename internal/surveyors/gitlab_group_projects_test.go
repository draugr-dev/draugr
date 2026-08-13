package surveyors

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestGitLabGroupProjectsInfo(t *testing.T) {
	info := NewGitLabGroupProjects().Info()
	if info.Name != "gitlab-group-projects" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Provides) != 1 || info.Provides[0] != plugin.TargetRepository {
		t.Errorf("provides = %v, want repositories", info.Provides)
	}
}

func TestGitLabGroupProjectsRequiresGroup(t *testing.T) {
	_, err := NewGitLabGroupProjects().Survey(context.Background(), plugin.SurveyScope{})
	if err == nil {
		t.Fatal("expected an error when the group is missing")
	}
}

func TestGitLabGroupProjectsSurvey(t *testing.T) {
	var gotToken, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("PRIVATE-TOKEN")
		gotPath, gotQuery = r.URL.EscapedPath(), r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "1" {
			w.Header().Set("x-next-page", "2")
			_, _ = fmt.Fprint(w, `[{"path":"api","path_with_namespace":"acme/api",
				"http_url_to_repo":"https://gitlab.com/acme/api.git","default_branch":"main"}]`)
			return
		}
		_, _ = fmt.Fprint(w, `[{"path":"web","path_with_namespace":"acme/team/web",
			"http_url_to_repo":"https://gitlab.com/acme/team/web.git","default_branch":"develop"}]`)
	}))
	defer srv.Close()

	g := GitLabGroupProjects{baseURL: srv.URL, httpClient: srv.Client()}
	frag, err := g.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme", Config: plugin.Config{"token": "glpat-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.Components) != 2 {
		t.Fatalf("want both pages' projects, got %d", len(frag.Components))
	}
	if frag.Components[0].Name != "api" ||
		frag.Components[0].Repositories[0].URL != "https://gitlab.com/acme/api.git" ||
		frag.Components[0].Repositories[0].Revision != "main" {
		t.Errorf("first component = %+v", frag.Components[0])
	}
	// A project in a subgroup is still one component, named for the project rather than the path.
	if frag.Components[1].Name != "web" || frag.Components[1].Repositories[0].Revision != "develop" {
		t.Errorf("second component = %+v", frag.Components[1])
	}
	if gotToken != "glpat-secret" {
		t.Errorf("PRIVATE-TOKEN = %q — GitLab authenticates access tokens with this header", gotToken)
	}
	if !strings.Contains(gotQuery, "include_subgroups=true") {
		t.Errorf("query = %q — a group is a tree, and stopping at the top level returns a fraction of it", gotQuery)
	}
	if want := "/groups/acme/projects"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestGitLabGroupProjectsEscapesANestedGroup(t *testing.T) {
	// A group may itself sit inside another, and every slash has to reach GitLab as %2F or the
	// request names something else — a 404 that reads like a missing group.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()

	g := GitLabGroupProjects{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := g.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme/platform", Config: plugin.Config{"token": "t"},
	}); err != nil {
		t.Fatal(err)
	}
	if want := "/groups/acme%2Fplatform/projects"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestGitLabGroupProjectsSkipsWhatCannotBeScanned(t *testing.T) {
	// An archived project is read-only and usually nobody's to fix; an empty one has no commits and
	// would fail the clone. Both are skipped, and both are reported — a component absent for a good
	// reason still looks like one that was missed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[
			{"path":"live","path_with_namespace":"acme/live","http_url_to_repo":"https://g/live.git","default_branch":"main"},
			{"path":"old","path_with_namespace":"acme/old","http_url_to_repo":"https://g/old.git","default_branch":"main","archived":true},
			{"path":"blank","path_with_namespace":"acme/blank","http_url_to_repo":"https://g/blank.git","empty_repo":true}
		]`)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	g := GitLabGroupProjects{baseURL: srv.URL, httpClient: srv.Client()}
	frag, err := g.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme", Config: plugin.Config{"token": "t"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.Components) != 1 || frag.Components[0].Name != "live" {
		t.Fatalf("components = %+v, want only the scannable one", frag.Components)
	}
	out := logs.String()
	for _, want := range []string{"acme/old", "archived", "acme/blank", "no commits"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log should say what was skipped and why, missing %q:\n%s", want, out)
		}
	}
}

func TestGitLabGroupProjectsWarnsWhenUnauthenticated(t *testing.T) {
	// Without a token GitLab returns the group's public projects and nothing else. The descriptor
	// is valid, the scan runs, and every private project is simply not in it — nobody reading that
	// output has a reason to suspect a gap.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[{"path":"public","http_url_to_repo":"https://g/p.git","default_branch":"main"}]`)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)
	t.Setenv("GITLAB_TOKEN", "")

	g := GitLabGroupProjects{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := g.Survey(context.Background(), plugin.SurveyScope{Ref: "acme"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "public projects only") {
		t.Errorf("an unauthenticated survey has to say what it could not see:\n%s", logs.String())
	}
}

func TestGitLabGroupProjectsStaysQuietWithAToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	g := GitLabGroupProjects{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := g.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme", Config: plugin.Config{"token": "t"},
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "public projects only") {
		t.Errorf("an authenticated survey warned anyway:\n%s", logs.String())
	}
}

func TestGitLabGroupProjectsReadsTheTokenFromTheEnvironment(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("PRIVATE-TOKEN")
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	t.Setenv("GITLAB_TOKEN", "from-env")

	g := GitLabGroupProjects{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := g.Survey(context.Background(), plugin.SurveyScope{Ref: "acme"}); err != nil {
		t.Fatal(err)
	}
	if gotToken != "from-env" {
		t.Errorf("PRIVATE-TOKEN = %q, want the value from GITLAB_TOKEN", gotToken)
	}
}

func TestGitLabGroupProjectsSurfacesAnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	g := GitLabGroupProjects{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := g.Survey(context.Background(), plugin.SurveyScope{Ref: "acme", Config: plugin.Config{"token": "t"}})
	if err == nil {
		t.Fatal("a refused survey reported success, so the descriptor would be silently empty")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("the error should carry the status: %v", err)
	}
}

func TestGitLabGroupProjectsSurfacesAnUnreadableResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html>sign in</html>`)
	}))
	defer srv.Close()

	g := GitLabGroupProjects{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := g.Survey(context.Background(), plugin.SurveyScope{Ref: "acme", Config: plugin.Config{"token": "t"}})
	if err == nil {
		t.Fatal("an undecodable listing was treated as an empty group")
	}
}

func TestGitLabAPIRootFollowsTheInstance(t *testing.T) {
	// Defaulting to gitlab.com without looking would survey the wrong host and produce a
	// descriptor that looks entirely fine.
	cases := []struct{ name, api, gitlabURL, server, want string }{
		{"a runner's api url wins", "https://git.acme.com/api/v4", "", "https://ignored", "https://git.acme.com/api/v4"},
		{"trailing slash trimmed", "https://git.acme.com/api/v4/", "", "", "https://git.acme.com/api/v4"},
		{"GITLAB_URL derives it", "", "https://git.acme.com/", "", "https://git.acme.com/api/v4"},
		{"a runner's server url derives it", "", "", "https://git.acme.com", "https://git.acme.com/api/v4"},
		{"nothing means gitlab.com", "", "", "", "https://gitlab.com/api/v4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CI_API_V4_URL", tc.api)
			t.Setenv("GITLAB_URL", tc.gitlabURL)
			t.Setenv("CI_SERVER_URL", tc.server)
			if got := gitlabAPIRoot(); got != tc.want {
				t.Errorf("gitlabAPIRoot() = %q, want %q", got, tc.want)
			}
		})
	}
}
