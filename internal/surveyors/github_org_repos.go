package surveyors

import (
	"context"
	"encoding/json"
	"fmt"
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
	return &GitHubOrgRepos{baseURL: "https://api.github.com", httpClient: http.DefaultClient}
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
