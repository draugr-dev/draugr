package surveyors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// GitHubOrgRepos discovers the repositories in a GitHub organization and returns them as
// Saga components (one per repository).
type GitHubOrgRepos struct {
	baseURL    string
	httpClient *http.Client
}

// NewGitHubOrgRepos returns the github-org-repos surveyor targeting github.com.
func NewGitHubOrgRepos() *GitHubOrgRepos {
	return &GitHubOrgRepos{baseURL: githubAPIRoot(), httpClient: http.DefaultClient}
}

// githubAPIRoot resolves the API root, so GitHub Enterprise Server needs no code change.
//
// GITHUB_API_URL is the same variable the github-pr-comment publisher reads, and Actions sets it
// on a GHES runner — so one variable configures both halves of the integration and a survey run in
// CI needs nothing configured at all. Anyone who has pointed the publisher at their own instance
// has every reason to expect the survey to follow, and a survey that quietly went to github.com
// instead would either fail on the org name or, worse, describe a public organization that happens
// to share it.
//
// The value is used exactly as given: GHES serves its API under /api/v3 and GITHUB_API_URL already
// carries that path, so appending a suffix would break the thing this is here to fix.
func githubAPIRoot() string {
	if u := os.Getenv("GITHUB_API_URL"); u != "" {
		return trimSlash(u)
	}
	return "https://api.github.com"
}

// Info identifies the surveyor.
func (GitHubOrgRepos) Info() plugin.SurveyorInfo {
	return plugin.SurveyorInfo{
		Name:     "github-org-repos",
		Provides: []plugin.TargetKind{plugin.TargetRepository},
	}
}

type ghRepo struct {
	Name          string `json:"name"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
}

// Survey lists the org's repositories. The org is taken from scope.Ref; an auth token is
// read from scope.Config["token"] or the GITHUB_TOKEN environment variable.
func (g GitHubOrgRepos) Survey(ctx context.Context, scope plugin.SurveyScope) (saga.Fragment, error) {
	org := scope.Ref
	if org == "" {
		return saga.Fragment{}, fmt.Errorf("github-org-repos: scope ref (org) is required")
	}

	token, _ := scope.Config["token"].(string)
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	repos, err := g.fetch(ctx, org, token)
	if err != nil {
		return saga.Fragment{}, err
	}

	// Unauthenticated, GitHub answers with the org's public repositories and nothing else. The
	// descriptor that results is syntactically fine, every control is enabled, and the scan that
	// follows passes or fails on real findings — while every private repository, which is where
	// the interesting code usually is, is simply not in it. Nobody reviewing that output has a
	// reason to suspect a gap, so the survey has to say so itself.
	if token == "" {
		slog.Warn("surveyed GitHub without a token — public repositories only; "+
			"private ones are not in this descriptor. Set GITHUB_TOKEN to include them",
			"org", org, "repositories", len(repos))
	}

	frag := saga.Fragment{}
	for _, r := range repos {
		frag.Components = append(frag.Components, saga.Component{
			Name: r.Name,
			Repositories: []saga.Repository{
				{URL: r.CloneURL, Revision: r.DefaultBranch},
			},
		})
	}
	return frag, nil
}

func (g GitHubOrgRepos) fetch(ctx context.Context, org, token string) ([]ghRepo, error) {
	url := fmt.Sprintf("%s/orgs/%s/repos?per_page=100", g.baseURL, org)
	var all []ghRepo

	for url != "" {
		page, next, err := g.getPage(ctx, url, token)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		url = next
	}
	return all, nil
}

// getPage fetches one page of repos and returns it plus the next-page URL (empty when
// none). It closes the response body.
func (g GitHubOrgRepos) getPage(ctx context.Context, url, token string) ([]ghRepo, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // org-derived API URL by design
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("github-org-repos: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("github-org-repos: unexpected status %d", resp.StatusCode)
	}
	var page []ghRepo
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, "", fmt.Errorf("github-org-repos: decode: %w", err)
	}
	return page, nextLink(resp.Header.Get("Link")), nil
}

var nextLinkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink extracts the rel="next" URL from a Link header, or "" if absent.
func nextLink(header string) string {
	if m := nextLinkRe.FindStringSubmatch(header); m != nil {
		return m[1]
	}
	return ""
}
