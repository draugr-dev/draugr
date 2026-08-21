package surveyors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// AzureDevOpsRepos discovers the Git repositories in an Azure DevOps organization or project and
// returns them as Saga components (one per repository).
type AzureDevOpsRepos struct {
	baseURL    string
	httpClient *http.Client
}

// NewAzureDevOpsRepos returns the azure-devops-repos surveyor targeting dev.azure.com.
func NewAzureDevOpsRepos() *AzureDevOpsRepos {
	return &AzureDevOpsRepos{baseURL: azureDevOpsRoot(), httpClient: http.DefaultClient}
}

// azureDevOpsRoot resolves the instance, so Azure DevOps Server needs no code change.
//
// Server is not a variant of Services with a different hostname — it is reached as
// `https://{server}/{collection}`, and the collection is part of the path. AZURE_DEVOPS_URL takes
// whatever the instance actually is, up to but not including the organization or collection.
func azureDevOpsRoot() string {
	if u := os.Getenv("AZURE_DEVOPS_URL"); u != "" {
		return trimSlash(u)
	}
	return "https://dev.azure.com"
}

// Info identifies the surveyor.
func (AzureDevOpsRepos) Info() plugin.SurveyorInfo {
	return plugin.SurveyorInfo{
		Name:     "azure-devops-repos",
		Provides: []plugin.TargetKind{plugin.TargetRepository},
	}
}

// adoRepo is the part of GitRepository this surveyor reads.
type adoRepo struct {
	Name string `json:"name"`
	// RemoteURL is the HTTPS clone URL. `url` is the API's own self-link and clones nothing.
	RemoteURL string `json:"remoteUrl"`
	// DefaultBranch arrives fully qualified ("refs/heads/main") and is absent on a repository
	// with no commits.
	DefaultBranch string `json:"defaultBranch"`
	IsDisabled    bool   `json:"isDisabled"`
	Project       struct {
		Name string `json:"name"`
	} `json:"project"`
}

// adoRepoList is the envelope every Azure DevOps list endpoint returns. It is not a bare array,
// and decoding it as one yields zero repositories with no error — a descriptor with no components
// and nothing to explain it.
type adoRepoList struct {
	Count int       `json:"count"`
	Value []adoRepo `json:"value"`
}

// Survey lists the organization's repositories.
//
// scope.Ref is "org" or "org/project". Both are useful and they answer different questions: an
// organization holds many projects, and surveying one project describes one team's surface while
// surveying the organization describes the estate. Azure DevOps makes the project segment
// optional for exactly this reason, so Draugr passes the choice through rather than making it.
//
// An auth token is read from scope.Config["token"], then $AZURE_DEVOPS_EXT_PAT (what the az CLI
// uses), then $AZURE_DEVOPS_TOKEN.
func (a AzureDevOpsRepos) Survey(ctx context.Context, scope plugin.SurveyScope) (saga.Fragment, error) {
	ref := strings.Trim(scope.Ref, "/")
	if ref == "" {
		return saga.Fragment{}, fmt.Errorf(
			"azure-devops-repos: scope ref is required: the organization, or \"organization/project\"")
	}

	token, _ := scope.Config["token"].(string)
	for _, env := range []string{"AZURE_DEVOPS_EXT_PAT", "AZURE_DEVOPS_TOKEN"} {
		if token != "" {
			break
		}
		token = os.Getenv(env)
	}

	repos, err := a.fetch(ctx, ref, token)
	if err != nil {
		return saga.Fragment{}, err
	}

	// Unauthenticated, Azure DevOps answers for public projects and nothing else. The descriptor
	// that results is syntactically fine, every control is enabled, and the scan that follows
	// passes or fails on real findings — while every private repository, which is where the
	// interesting code usually is, is simply not in it. Nobody reviewing that output has a reason
	// to suspect a gap, so the survey has to say so itself.
	if token == "" {
		slog.Warn("surveyed without a token",
			"visibility", "public projects only",
			"fix", "set AZURE_DEVOPS_EXT_PAT to include private repositories",
			"scope", ref, "repositories", len(repos))
	}

	frag := saga.Fragment{}
	for _, r := range repos {
		// A disabled repository cannot be cloned; one with no commits has nothing to scan and the
		// clone would fail. Both are skipped and counted rather than dropped in silence, because a
		// component that is absent for a good reason still looks like one that was missed.
		if reason := adoSkipReason(r); reason != "" {
			slog.Info("skipping repository", "repository", r.Project.Name+"/"+r.Name, "reason", reason)
			continue
		}
		frag.Components = append(frag.Components, saga.Component{
			Name: r.Name,
			Repositories: []saga.Repository{
				{URL: r.RemoteURL, Revision: shortBranch(r.DefaultBranch)},
			},
		})
	}
	return frag, nil
}

// adoSkipReason says why a repository cannot be scanned, or "" when it can.
func adoSkipReason(r adoRepo) string {
	switch {
	case r.IsDisabled:
		return "disabled"
	case r.DefaultBranch == "":
		return "no commits"
	case r.RemoteURL == "":
		return "no clone URL"
	}
	return ""
}

// shortBranch turns a fully qualified ref into the branch name a clone expects.
//
// Azure DevOps reports "refs/heads/main" where the other forges report "main". Passed through
// unchanged it reaches `git clone --branch refs/heads/main`, which fails — and it fails at scan
// time, in a descriptor that was written by a survey and looks correct in review.
func shortBranch(ref string) string {
	return strings.TrimPrefix(ref, "refs/heads/")
}

// fetch lists the repositories in scope.
//
// One request: unlike the paged forges, the Azure DevOps repositories endpoint returns the whole
// list and offers no continuation token. Adding paging "just in case" would mean writing a loop
// against a header the API does not send, which is a loop nothing can test and nothing executes.
func (a AzureDevOpsRepos) fetch(ctx context.Context, ref, token string) ([]adoRepo, error) {
	// Each path segment escaped separately: an organization or project name may contain a space,
	// and escaping the joined string would let a slash the caller typed become path structure.
	var segs []string
	for s := range strings.SplitSeq(ref, "/") {
		if s != "" {
			segs = append(segs, url.PathEscape(s))
		}
	}
	if len(segs) > 2 {
		return nil, fmt.Errorf(
			"azure-devops-repos: scope ref %q has too many segments: expected \"organization\" or "+
				"\"organization/project\"", ref)
	}
	endpoint := fmt.Sprintf("%s/%s/_apis/git/repositories?api-version=7.1",
		a.baseURL, strings.Join(segs, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) //nolint:gosec // scope-derived API URL by design
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		// Basic with an empty username: Azure DevOps carries the PAT in the password field and
		// ignores the username. Sending it as a bearer instead is one of the ways to arrive at the
		// 203 handled below.
		req.Header.Set("Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(":"+token)))
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure-devops-repos: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := adoStatusError(resp.StatusCode, ref, token); err != nil {
		return nil, err
	}
	var list adoRepoList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("azure-devops-repos: decode: %w", err)
	}
	return list.Value, nil
}

// adoStatusError turns a response status into something a reader can act on.
//
// Azure DevOps answers an unauthenticated or under-scoped API request with **203 Non-Authoritative
// Information** and a sign-in page, rather than a 401. Reported as "unexpected status 203" that is
// worse than useless: 203 means "this is fine, from a cache" to anyone who looks it up, and the
// actual problem — a token that is missing, malformed, or lacks the Code (read) scope — is named
// nowhere.
func adoStatusError(status int, ref, token string) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusNonAuthoritativeInfo, http.StatusUnauthorized:
		if token == "" {
			return fmt.Errorf("azure-devops-repos: %s needs authentication (HTTP %d): set "+
				"AZURE_DEVOPS_EXT_PAT to a personal access token with the Code (read) scope",
				ref, status)
		}
		return fmt.Errorf("azure-devops-repos: the token was rejected for %s (HTTP %d): it is "+
			"expired, or lacks the Code (read) scope, or belongs to a different organization",
			ref, status)
	case http.StatusNotFound:
		return fmt.Errorf("azure-devops-repos: %s not found (HTTP 404) — Azure DevOps answers 404 "+
			"for a scope the token cannot see as well as for one that does not exist", ref)
	case http.StatusTooManyRequests:
		return fmt.Errorf("azure-devops-repos: rate limited by Azure DevOps (HTTP 429) — retry " +
			"after the interval in the response's Retry-After header")
	}
	return fmt.Errorf("azure-devops-repos: unexpected status %d", status)
}
