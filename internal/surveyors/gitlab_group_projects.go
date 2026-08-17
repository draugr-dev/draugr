package surveyors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// GitLabGroupProjects discovers the projects in a GitLab group and returns them as Saga
// components (one per project).
type GitLabGroupProjects struct {
	baseURL    string
	httpClient *http.Client
}

// NewGitLabGroupProjects returns the gitlab-group-projects surveyor targeting gitlab.com.
func NewGitLabGroupProjects() *GitLabGroupProjects {
	return &GitLabGroupProjects{baseURL: gitlabAPIRoot(), httpClient: http.DefaultClient}
}

// gitlabAPIRoot resolves the API v4 root, so a self-managed instance needs no code change.
//
// CI_API_V4_URL is what a GitLab runner sets and already carries the path; CI_SERVER_URL is what
// remains when the survey runs outside a pipeline against the same instance. Defaulting to
// gitlab.com without looking would survey the wrong host and produce a descriptor that looks fine.
func gitlabAPIRoot() string {
	if api := os.Getenv("CI_API_V4_URL"); api != "" {
		return trimSlash(api)
	}
	if server := os.Getenv("GITLAB_URL"); server != "" {
		return trimSlash(server) + "/api/v4"
	}
	if server := os.Getenv("CI_SERVER_URL"); server != "" {
		return trimSlash(server) + "/api/v4"
	}
	return "https://gitlab.com/api/v4"
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// Info identifies the surveyor.
func (GitLabGroupProjects) Info() plugin.SurveyorInfo {
	return plugin.SurveyorInfo{
		Name:     "gitlab-group-projects",
		Provides: []plugin.TargetKind{plugin.TargetRepository},
	}
}

type glProject struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	PathNamespace string `json:"path_with_namespace"`
	HTTPURL       string `json:"http_url_to_repo"`
	DefaultBranch string `json:"default_branch"`
	Archived      bool   `json:"archived"`
	EmptyRepo     bool   `json:"empty_repo"`
}

// Survey lists the group's projects. The group is taken from scope.Ref; an auth token is read
// from scope.Config["token"] or the GITLAB_TOKEN environment variable.
func (g GitLabGroupProjects) Survey(ctx context.Context, scope plugin.SurveyScope) (saga.Fragment, error) {
	group := scope.Ref
	if group == "" {
		return saga.Fragment{}, fmt.Errorf("gitlab-group-projects: scope ref (group) is required")
	}

	token, _ := scope.Config["token"].(string)
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}

	projects, err := g.fetch(ctx, group, token)
	if err != nil {
		return saga.Fragment{}, err
	}

	// Unauthenticated, GitLab answers with the group's public projects and nothing else. The
	// descriptor that results is syntactically fine, every control is enabled, and the scan that
	// follows passes or fails on real findings — while every private project, which is where the
	// interesting code usually is, is simply not in it. Nobody reviewing that output has a reason
	// to suspect a gap, so the survey has to say so itself.
	if token == "" {
		slog.Warn("surveyed GitLab without a token — public projects only; "+
			"private ones are not in this descriptor. Set GITLAB_TOKEN to include them",
			"group", group, "projects", len(projects))
	}

	frag := saga.Fragment{}
	for _, p := range projects {
		// An archived project is read-only and usually nobody's to fix; an empty one has nothing to
		// scan and would fail the clone. Both are skipped and counted rather than dropped in
		// silence, because a component that is absent for a good reason still looks like one that
		// was missed.
		if p.Archived || p.EmptyRepo {
			slog.Info("skipping project", "project", p.PathNamespace,
				"reason", skipReason(p))
			continue
		}
		frag.Components = append(frag.Components, saga.Component{
			Name: p.Path,
			Repositories: []saga.Repository{
				{URL: p.HTTPURL, Revision: p.DefaultBranch},
			},
		})
	}
	return frag, nil
}

func skipReason(p glProject) string {
	if p.Archived {
		return "archived"
	}
	return "no commits"
}

// fetch pages through the group's projects, subgroups included.
//
// include_subgroups is not optional. A group is a tree, and a survey that stopped at the top level
// would return a fraction of it and say nothing about the rest — the descriptor would look like the
// whole organization and describe one floor of it.
func (g GitLabGroupProjects) fetch(ctx context.Context, group, token string) ([]glProject, error) {
	var all []glProject
	for page := 1; page != 0; {
		batch, next, err := g.getPage(ctx, group, token, page)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		page = next
	}
	return all, nil
}

// getPage fetches one page of projects and returns it plus the next page number (0 when none).
func (g GitLabGroupProjects) getPage(ctx context.Context, group, token string, page int) ([]glProject, int, error) {
	// A group path may itself be nested, and every slash in it has to reach GitLab as %2F or the
	// request names something else entirely.
	endpoint := fmt.Sprintf("%s/groups/%s/projects?include_subgroups=true&per_page=100&page=%d",
		g.baseURL, url.PathEscape(group), page)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) //nolint:gosec // group-derived API URL by design
	if err != nil {
		return nil, 0, err
	}
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("gitlab-group-projects: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("gitlab-group-projects: unexpected status %d", resp.StatusCode)
	}
	var batch []glProject
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return nil, 0, fmt.Errorf("gitlab-group-projects: decode: %w", err)
	}
	next, _ := strconv.Atoi(resp.Header.Get("x-next-page"))
	return batch, next, nil
}
