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

// adoEnv sets what an Azure Pipelines pull-request build provides.
func adoEnv(t *testing.T, collection string) {
	t.Helper()
	t.Setenv("TF_BUILD", "True")
	t.Setenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", collection+"/")
	t.Setenv("SYSTEM_TEAMPROJECT", "integration")
	t.Setenv("BUILD_REPOSITORY_NAME", "integration")
	t.Setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "42")
	t.Setenv("SYSTEM_ACCESSTOKEN", "pat-not-a-jwt")
}

func TestAzurePRCommentCreatesAThreadWhenNoneExists(t *testing.T) {
	var method, path, content string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"value":[]}`))
			return
		}
		method, path = r.Method, r.URL.Path
		var b struct {
			Comments []struct{ Content string } `json:"comments"`
			Status   string                     `json:"status"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if len(b.Comments) > 0 {
			content = b.Comments[0].Content
		}
		_, _ = w.Write([]byte(`{"id":7}`))
	}))
	defer srv.Close()
	adoEnv(t, srv.URL)

	p, err := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %s, want POST", method)
	}
	// Azure nests comments in a thread, so the path is the thread collection rather than a
	// comment collection — getting this wrong is a 404 that reads like a missing pull request.
	if want := "/integration/_apis/git/repositories/integration/pullRequests/42/threads"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if !strings.Contains(content, defaultPRMarker) {
		t.Errorf("the marker is what makes the next run an edit rather than a duplicate: %q", content)
	}
	if !strings.Contains(content, "Draugr diff") {
		t.Errorf("content = %q", content)
	}
}

func TestAzurePRCommentEditsTheExistingCommentInPlace(t *testing.T) {
	var method, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"value":[
				{"id":3,"comments":[{"id":9,"content":"a reviewer said something"}]},
				{"id":5,"comments":[{"id":11,"content":"` + defaultPRMarker + `\nold report"}]}
			]}`))
			return
		}
		method, path = r.Method, r.URL.Path
		_, _ = w.Write([]byte(`{"id":11}`))
	}))
	defer srv.Close()
	adoEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPatch {
		t.Errorf("method = %s, want PATCH — a second push must not add a second thread", method)
	}
	if !strings.HasSuffix(path, "/threads/5/comments/11") {
		t.Errorf("edited %q, want the marked thread's first comment", path)
	}
}

func TestAzurePRCommentIgnoresTheMarkerInAReply(t *testing.T) {
	// A reviewer quoting the report puts the marker in a *reply*. Matching it would make Draugr
	// overwrite someone's words on the next run, which is worse than posting a duplicate.
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"value":[{"id":3,"comments":[
				{"id":9,"content":"about this:"},
				{"id":10,"content":"quoting ` + defaultPRMarker + ` here"}
			]}]}`))
			return
		}
		method = r.Method
		_, _ = w.Write([]byte(`{"id":12}`))
	}))
	defer srv.Close()
	adoEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %s, want POST — a reply is not Draugr's own comment", method)
	}
}

func TestAzurePRCommentAuthorizesByCredentialKind(t *testing.T) {
	// The pipeline's own token is a JWT and must go in as a bearer; a personal access token goes
	// in as basic auth. Sending one as the other is a 401 with nothing to explain it.
	cases := []struct {
		name, token, wantPrefix string
	}{
		{"pipeline access token", "eyJhbGciOiJSUzI1NiJ9.e30.sig", "Bearer "},
		{"personal access token", "abcdef0123456789", "Basic "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Get("Authorization")
				_, _ = w.Write([]byte(`{"value":[]}`))
			}))
			defer srv.Close()
			adoEnv(t, srv.URL)
			t.Setenv("SYSTEM_ACCESSTOKEN", tc.token)

			p, _ := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
			_ = p.Publish(context.Background(), []report.Artifact{mdArtifact()})
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("Authorization = %q, want the %s scheme", got, strings.TrimSpace(tc.wantPrefix))
			}
			if strings.Contains(got, tc.token) && tc.wantPrefix == "Basic " {
				t.Error("a PAT must be base64-encoded after a colon, not sent raw")
			}
		})
	}
}

func TestAzurePRCommentNamesTheAccessTokenMapping(t *testing.T) {
	// SYSTEM_ACCESSTOKEN is the one pipeline variable not exposed to a script step by default,
	// and it is by far the most common reason this publisher cannot authenticate. An error that
	// only says "missing token" sends someone looking in the wrong place.
	t.Setenv("TF_BUILD", "True")
	t.Setenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "https://dev.azure.com/acme/")
	t.Setenv("SYSTEM_TEAMPROJECT", "proj")
	t.Setenv("BUILD_REPOSITORY_NAME", "repo")
	t.Setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "42")
	t.Setenv("SYSTEM_ACCESSTOKEN", "")

	_, err := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "System.AccessToken") {
		t.Errorf("the error should name the fix: %v", err)
	}
}

func TestAzurePRCommentNoopWithoutAPullRequest(t *testing.T) {
	// A push build carrying the same Saga must not fail, or a project needs two descriptors.
	t.Setenv("TF_BUILD", "True")
	t.Setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "")
	p, err := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), nil); err != nil {
		t.Errorf("a no-op publisher returned an error: %v", err)
	}
	if p.Kind() != "azure-pr-comment" {
		t.Errorf("Kind() = %q", p.Kind())
	}
}

func TestAzurePRCommentNoopOutsideAzure(t *testing.T) {
	// Same Saga on a laptop.
	t.Setenv("TF_BUILD", "")
	t.Setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "")
	p, err := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), nil); err != nil {
		t.Errorf("a no-op publisher returned an error: %v", err)
	}
}

func TestAzurePRCommentRequiresMarkdown(t *testing.T) {
	adoEnv(t, "https://dev.azure.com/acme")
	p, _ := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
	err := p.Publish(context.Background(), []report.Artifact{{Format: "sarif", Bytes: []byte("{}")}})
	if err == nil || !strings.Contains(err.Error(), "markdown") {
		t.Errorf("a PR comment has nothing to say without a markdown report: %v", err)
	}
}

func TestAzurePRCommentSurfacesAForbiddenAsAPermission(t *testing.T) {
	// 403 here means the token is valid but the build identity cannot write. The fix is a
	// repository permission, and the message says so rather than leaving someone re-checking
	// their token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"value":[]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"denied"}`))
	}))
	defer srv.Close()
	adoEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
	err := p.Publish(context.Background(), []report.Artifact{mdArtifact()})
	if err == nil || !strings.Contains(err.Error(), "Contribute to pull requests") {
		t.Errorf("the error should name the permission: %v", err)
	}
}

func TestAzurePRCommentSurfacesAListFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	adoEnv(t, srv.URL)

	p, _ := For(saga.PublisherConfig{Kind: "azure-pr-comment"})
	if err := p.Publish(context.Background(), []report.Artifact{mdArtifact()}); err == nil {
		t.Error("a failed lookup was swallowed, which would post a duplicate every run")
	}
}

func TestAzurePRCommentExplicitConfigBeatsTheEnvironment(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// EscapedPath, not Path: the point is what went on the wire. Path is already decoded, so
		// asserting on it would pass whether or not the name was escaped.
		path = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()
	adoEnv(t, "https://dev.azure.com/wrong")

	p, err := For(saga.PublisherConfig{
		Kind: "azure-pr-comment", Org: srv.URL, Project: "other", Repo: "repo two", PR: 99,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Publish(context.Background(), []report.Artifact{mdArtifact()})
	// A repository name with a space is legal in Azure and has to survive into the URL.
	if want := "/other/_apis/git/repositories/repo%20two/pullRequests/99/threads"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}
