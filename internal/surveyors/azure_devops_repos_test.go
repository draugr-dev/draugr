package surveyors

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// twoProjectsBody is the shape Azure DevOps actually returns: an envelope, a fully qualified
// default branch, and two repositories in two different projects.
const twoProjectsBody = `{"count":2,"value":[
	{"name":"api","remoteUrl":"https://dev.azure.com/acme/Platform/_git/api",
	 "defaultBranch":"refs/heads/main","project":{"name":"Platform"}},
	{"name":"web","remoteUrl":"https://dev.azure.com/acme/Storefront/_git/web",
	 "defaultBranch":"refs/heads/develop","project":{"name":"Storefront"}}
]}`

func TestAzureDevOpsReposInfo(t *testing.T) {
	info := NewAzureDevOpsRepos().Info()
	if info.Name != "azure-devops-repos" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Provides) != 1 || info.Provides[0] != plugin.TargetRepository {
		t.Errorf("provides = %v, want repositories", info.Provides)
	}
}

func TestAzureDevOpsReposRequiresAScope(t *testing.T) {
	for _, ref := range []string{"", "/", "   "} {
		if _, err := NewAzureDevOpsRepos().Survey(context.Background(), plugin.SurveyScope{Ref: ref}); err == nil {
			t.Errorf("Ref %q was accepted; without an organization there is nothing to survey", ref)
		}
	}
}

func TestAzureDevOpsReposSurvey(t *testing.T) {
	// Two repositories in two projects. One proves the loop runs; two prove nothing collapses a
	// per-repository value into a per-organization one and picks a winner.
	var gotAuth, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath, gotQuery = r.URL.EscapedPath(), r.URL.RawQuery
		_, _ = fmt.Fprint(w, twoProjectsBody)
	}))
	defer srv.Close()

	a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
	frag, err := a.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme", Config: plugin.Config{"token": "pat-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.Components) != 2 {
		t.Fatalf("want one component per repository, got %d", len(frag.Components))
	}
	// Each keeps its own clone URL and its own branch: a second repository must not inherit the
	// first's, which is the failure a single-repository fixture cannot see.
	want := []struct{ name, url, rev string }{
		{"api", "https://dev.azure.com/acme/Platform/_git/api", "main"},
		{"web", "https://dev.azure.com/acme/Storefront/_git/web", "develop"},
	}
	for i, w := range want {
		got := frag.Components[i]
		if got.Name != w.name || got.Repositories[0].URL != w.url || got.Repositories[0].Revision != w.rev {
			t.Errorf("component %d = %+v, want %+v", i, got, w)
		}
	}
	if wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(":pat-secret")); gotAuth != wantAuth {
		t.Errorf("Authorization = %q, want %q — Azure DevOps carries the PAT in the password "+
			"field of Basic auth, and a bearer is one of the ways to get a 203", gotAuth, wantAuth)
	}
	if want := "/acme/_apis/git/repositories"; gotPath != want {
		t.Errorf("path = %q, want %q — no project segment means the whole organization", gotPath, want)
	}
	if !strings.Contains(gotQuery, "api-version=7.1") {
		t.Errorf("query = %q — Azure DevOps requires an explicit api-version on every request", gotQuery)
	}
}

func TestAzureDevOpsReposScopesToOneProject(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = fmt.Fprint(w, `{"count":0,"value":[]}`)
	}))
	defer srv.Close()

	a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := a.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme/Platform", Config: plugin.Config{"token": "t"},
	}); err != nil {
		t.Fatal(err)
	}
	if want := "/acme/Platform/_apis/git/repositories"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestAzureDevOpsReposEscapesEachSegment(t *testing.T) {
	// Azure DevOps project names may contain spaces. Escaped as one string the slash would be
	// encoded too and the request would name a project called "acme/My Team"; unescaped, the space
	// makes an invalid request line.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = fmt.Fprint(w, `{"count":0,"value":[]}`)
	}))
	defer srv.Close()

	a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := a.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme/My Team", Config: plugin.Config{"token": "t"},
	}); err != nil {
		t.Fatal(err)
	}
	if want := "/acme/My%20Team/_apis/git/repositories"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestAzureDevOpsReposRejectsATooDeepScope(t *testing.T) {
	a := AzureDevOpsRepos{baseURL: "https://example.invalid", httpClient: http.DefaultClient}
	_, err := a.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme/Platform/extra", Config: plugin.Config{"token": "t"},
	})
	if err == nil {
		t.Fatal("a three-segment scope was accepted; it would build a URL for something else")
	}
	if !strings.Contains(err.Error(), "organization/project") {
		t.Errorf("the error should say what a scope looks like: %v", err)
	}
}

func TestAzureDevOpsReposShortensTheDefaultBranch(t *testing.T) {
	// Azure DevOps reports refs/heads/main where the other forges report main. Passed through it
	// reaches `git clone --branch refs/heads/main`, which fails at scan time — in a descriptor a
	// survey wrote, that looks correct in review.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"count":1,"value":[{"name":"api","remoteUrl":"https://d/api",
			"defaultBranch":"refs/heads/release/2.0"}]}`)
	}))
	defer srv.Close()

	a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
	frag, err := a.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme", Config: plugin.Config{"token": "t"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A branch with a slash in its own name keeps it: only the refs/heads/ prefix goes.
	if got := frag.Components[0].Repositories[0].Revision; got != "release/2.0" {
		t.Errorf("revision = %q, want %q", got, "release/2.0")
	}
}

func TestAzureDevOpsReposSkipsWhatCannotBeScanned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"count":4,"value":[
			{"name":"live","remoteUrl":"https://d/live","defaultBranch":"refs/heads/main","project":{"name":"P"}},
			{"name":"off","remoteUrl":"https://d/off","defaultBranch":"refs/heads/main","isDisabled":true,"project":{"name":"P"}},
			{"name":"blank","remoteUrl":"https://d/blank","project":{"name":"P"}},
			{"name":"nourl","defaultBranch":"refs/heads/main","project":{"name":"P"}}
		]}`)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
	frag, err := a.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme", Config: plugin.Config{"token": "t"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.Components) != 1 || frag.Components[0].Name != "live" {
		t.Fatalf("components = %+v, want only the scannable one", frag.Components)
	}
	out := logs.String()
	for _, want := range []string{"P/off", "disabled", "P/blank", "no commits", "P/nourl", "no clone URL"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log should say what was skipped and why, missing %q:\n%s", want, out)
		}
	}
}

func TestAzureDevOpsReposWarnsWhenUnauthenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"count":1,"value":[{"name":"pub","remoteUrl":"https://d/p","defaultBranch":"refs/heads/main"}]}`)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)
	t.Setenv("AZURE_DEVOPS_EXT_PAT", "")
	t.Setenv("AZURE_DEVOPS_TOKEN", "")

	a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := a.Survey(context.Background(), plugin.SurveyScope{Ref: "acme"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "public projects only") {
		t.Errorf("an unauthenticated survey has to say what it could not see:\n%s", logs.String())
	}
}

func TestAzureDevOpsReposStaysQuietWithAToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"count":0,"value":[]}`)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
	if _, err := a.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme", Config: plugin.Config{"token": "t"},
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "public projects only") {
		t.Errorf("an authenticated survey warned anyway:\n%s", logs.String())
	}
}

func TestAzureDevOpsReposReadsTheTokenFromTheEnvironment(t *testing.T) {
	// Both names, in order: AZURE_DEVOPS_EXT_PAT is what the az CLI already exports, so a machine
	// signed in to Azure DevOps needs nothing set for this.
	cases := []struct{ name, extPAT, token, want string }{
		{"the az CLI's variable", "from-ext", "", "from-ext"},
		{"the az CLI's variable wins", "from-ext", "from-token", "from-ext"},
		{"the fallback", "", "from-token", "from-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				_, _ = fmt.Fprint(w, `{"count":0,"value":[]}`)
			}))
			defer srv.Close()
			t.Setenv("AZURE_DEVOPS_EXT_PAT", tc.extPAT)
			t.Setenv("AZURE_DEVOPS_TOKEN", tc.token)

			a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
			if _, err := a.Survey(context.Background(), plugin.SurveyScope{Ref: "acme"}); err != nil {
				t.Fatal(err)
			}
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+tc.want))
			if gotAuth != want {
				t.Errorf("Authorization carried the wrong token: got %q, want the value from %q", gotAuth, tc.want)
			}
		})
	}
}

func TestAzureDevOpsReposExplainsAnAuthFailure(t *testing.T) {
	// Azure DevOps answers an unauthenticated or under-scoped API call with 203 and a sign-in
	// page, not a 401. "unexpected status 203" sends the reader to look up a code that means
	// "this is fine, from a cache" and names nothing they can fix.
	cases := []struct {
		name          string
		status        int
		token         string
		wantSubstring string
	}{
		{"203 without a token", http.StatusNonAuthoritativeInfo, "", "Code (read) scope"},
		{"203 with a token", http.StatusNonAuthoritativeInfo, "t", "rejected"},
		{"401 with a token", http.StatusUnauthorized, "t", "rejected"},
		{"404 hides permission", http.StatusNotFound, "t", "as well as for one that does not exist"},
		{"429 says to wait", http.StatusTooManyRequests, "t", "Retry-After"},
		{"anything else still surfaces", http.StatusInternalServerError, "t", "500"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, `<html>sign in</html>`)
			}))
			defer srv.Close()
			t.Setenv("AZURE_DEVOPS_EXT_PAT", "")
			t.Setenv("AZURE_DEVOPS_TOKEN", "")

			a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
			scope := plugin.SurveyScope{Ref: "acme"}
			if tc.token != "" {
				scope.Config = plugin.Config{"token": tc.token}
			}
			_, err := a.Survey(context.Background(), scope)
			if err == nil {
				t.Fatal("a refused survey reported success, so the descriptor would be silently empty")
			}
			if !strings.Contains(err.Error(), tc.wantSubstring) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantSubstring)
			}
		})
	}
}

func TestAzureDevOpsReposSurfacesAnUnreadableResponse(t *testing.T) {
	// A 200 carrying something that is not the envelope. Decoded as a bare array this would yield
	// zero repositories and no error — an empty descriptor with nothing to explain it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html>sign in</html>`)
	}))
	defer srv.Close()

	a := AzureDevOpsRepos{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := a.Survey(context.Background(), plugin.SurveyScope{
		Ref: "acme", Config: plugin.Config{"token": "t"},
	})
	if err == nil {
		t.Fatal("an undecodable listing was treated as an empty organization")
	}
}

func TestAzureDevOpsRootFollowsTheInstance(t *testing.T) {
	cases := []struct{ name, url, want string }{
		{"nothing means the hosted service", "", "https://dev.azure.com"},
		{"a server instance, with its collection", "https://tfs.acme.com/DefaultCollection",
			"https://tfs.acme.com/DefaultCollection"},
		{"trailing slash trimmed", "https://tfs.acme.com/DefaultCollection/",
			"https://tfs.acme.com/DefaultCollection"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AZURE_DEVOPS_URL", tc.url)
			if got := azureDevOpsRoot(); got != tc.want {
				t.Errorf("azureDevOpsRoot() = %q, want %q", got, tc.want)
			}
		})
	}
}
