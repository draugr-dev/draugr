package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// gitlabIssueBudget is the longest body written to a GitLab issue. GitLab documents 1,048,576
// characters for a description and 1,000,000 for a note, and a body is kept to the smaller.
const gitlabIssueBudget = 1_000_000

// GitLabIssueTypes are the values `item.type` takes on a gitlab-issue entry. GitLab's fourth,
// test_case, needs Ultimate.
var GitLabIssueTypes = []string{"issue", "incident", "task"}

// gitlabIssuePublisher keeps one GitLab issue open for each failing part of the gate and closes it
// when that part passes. The API root and project come from the runner, as for gitlab-mr-comment.
//
// An item is found by label and marker, as on GitHub. Filtering on the token's own user as well
// would take a permission a fine-grained token otherwise does not need, and would lose every open
// item the day the token moved to another user.
type gitlabIssuePublisher struct {
	cfg                    saga.PublisherConfig
	apiURL, project, token string
	label                  string
	client                 *http.Client
}

func newGitLabIssuePublisher(cfg saga.PublisherConfig) (Publisher, error) {
	tokenEnv := firstNonEmpty(cfg.TokenEnv, "GITLAB_TOKEN")
	p := gitlabIssuePublisher{
		cfg:     cfg,
		apiURL:  gitlabAPIURL(),
		project: firstNonEmpty(cfg.Repo, os.Getenv("CI_PROJECT_ID")),
		token:   os.Getenv(tokenEnv),
		label:   firstNonEmpty(cfg.Label, defaultIssueLabel),
		client:  newIssueClient(http.DefaultClient),
	}
	if os.Getenv("GITLAB_CI") != "true" && cfg.Repo == "" && p.token == "" {
		return skipPublisher{kind: "gitlab-issue", reason: "not a GitLab CI environment"}, nil
	}
	var missing []string
	if p.project == "" {
		missing = append(missing, "repo (or $CI_PROJECT_ID)")
	}
	if p.token == "" {
		// CI_JOB_TOKEN is in every job and cannot write issues, so it is the credential somebody
		// reaches for first.
		missing = append(missing, "$"+tokenEnv+", a masked CI/CD variable holding a token with Work Item: Create, "+
			"Read and Update, Label: Read and Member: Read, or the api scope, of a user with the Planner role. "+
			"CI_JOB_TOKEN cannot write issues")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("gitlab-issue publisher missing: %s", strings.Join(missing, "; "))
	}
	return p, nil
}

func (gitlabIssuePublisher) Kind() string { return "gitlab-issue" }

// Publish is never the path a run takes, since Run calls PublishRun. Without the run there is no
// gate to follow, so it refuses rather than doing nothing.
func (gitlabIssuePublisher) Publish(context.Context, []report.Artifact) error {
	return errors.New("gitlab-issue publisher follows the gate, and needs the run: call PublishRun")
}

// PublishRun opens, rewrites and closes the entry's issues to match the run.
func (p gitlabIssuePublisher) PublishRun(ctx context.Context, data report.Data, _ []report.Artifact) error {
	return trackIssues(ctx, p, data, p.cfg)
}

func (gitlabIssuePublisher) kind() string        { return "gitlab-issue" }
func (gitlabIssuePublisher) format() issueFormat { return markdownFormat{} }
func (gitlabIssuePublisher) budget() int         { return gitlabIssueBudget }
func (gitlabIssuePublisher) ref(n int64) string  { return "#" + strconv.FormatInt(n, 10) }

type gitlabUser struct {
	Username string `json:"username"`
}

type gitlabIssue struct {
	IID         int64        `json:"iid"`
	Description string       `json:"description"`
	Labels      []string     `json:"labels"`
	Assignees   []gitlabUser `json:"assignees"`
	Milestone   *struct {
		ID int64 `json:"id"`
	} `json:"milestone"`
	IssueType    string `json:"issue_type"`
	Confidential bool   `json:"confidential"`
}

// open lists the open issues carrying the tracking label, oldest first.
func (p gitlabIssuePublisher) open(ctx context.Context) ([]trackedItem, error) {
	q := url.Values{"labels": {p.label}, "state": {"opened"}, "order_by": {"created_at"}, "sort": {"asc"}, "per_page": {"100"}}
	var out []trackedItem
	for page := "1"; page != ""; {
		q.Set("page", page)
		var issues []gitlabIssue
		h, err := p.do(ctx, "list issues", http.MethodGet, p.projectURL("issues")+"?"+q.Encode(), nil, &issues)
		if err != nil {
			return nil, err
		}
		for _, i := range issues {
			out = append(out, trackedItem{Number: i.IID, Body: i.Description, Labels: i.Labels})
		}
		page = h.Get("X-Next-Page")
	}
	return out, nil
}

// create opens an issue with the tracking label, the configured metadata and the fact labels, then
// checks that GitLab kept the metadata. GitLab creates a label the project does not have.
func (p gitlabIssuePublisher) create(ctx context.Context, title, body string, facts []string) error {
	item := p.item()
	var labels []string
	for _, l := range append(append([]string{p.label}, item.Labels...), facts...) {
		if !containsFold(labels, l) {
			labels = append(labels, l)
		}
	}
	req := map[string]any{
		"title":        title,
		"description":  body,
		"labels":       strings.Join(labels, ","),
		"confidential": p.confidential(),
	}
	if item.Type != "" {
		req["issue_type"] = item.Type
	}
	// GitLab Free takes assignee_id and documents assignee_ids for Premium and Ultimate.
	var ids []int64
	for _, a := range item.Assignees {
		id, err := p.member(ctx, a)
		if err != nil {
			return err
		}
		ids = append(ids, id)
	}
	switch len(ids) {
	case 0:
	case 1:
		req["assignee_id"] = ids[0]
	default:
		req["assignee_ids"] = ids
	}
	var milestone int64
	if item.Milestone != "" {
		id, err := p.milestone(ctx, item.Milestone)
		if err != nil {
			return err
		}
		milestone = id
		req["milestone_id"] = id
	}
	var got gitlabIssue
	if _, err := p.do(ctx, "create an issue", http.MethodPost, p.projectURL("issues"), req, &got); err != nil {
		return err
	}

	var dropped []string
	for _, l := range labels {
		if !containsFold(got.Labels, l) {
			dropped = append(dropped, "label "+l)
		}
	}
	for _, a := range item.Assignees {
		if !slices.ContainsFunc(got.Assignees, func(g gitlabUser) bool { return strings.EqualFold(g.Username, a) }) {
			dropped = append(dropped, "assignee "+a)
		}
	}
	if milestone != 0 && (got.Milestone == nil || got.Milestone.ID != milestone) {
		dropped = append(dropped, "milestone "+item.Milestone)
	}
	why := "GitLab keeps one assignee on the Free tier, and drops metadata the token's user has no role to set"
	if item.Type != "" && !strings.EqualFold(got.IssueType, item.Type) {
		dropped = append(dropped, "type "+item.Type)
		if strings.EqualFold(item.Type, "incident") {
			why = "An incident needs the Reporter role, and GitLab creates an issue for a user without it"
		}
	}
	if got.Confidential != p.confidential() {
		dropped = append(dropped, "confidential "+strconv.FormatBool(p.confidential()))
	}
	if len(dropped) > 0 {
		return fmt.Errorf("gitlab-issue publisher: created #%d in %s without %s. %s", got.IID, p.project, strings.Join(dropped, ", "), why)
	}
	return nil
}

func (p gitlabIssuePublisher) rewrite(ctx context.Context, n int64, body string) error {
	_, err := p.do(ctx, "update #"+strconv.FormatInt(n, 10), http.MethodPut,
		p.issueURL(n), map[string]string{"description": body}, nil)
	return err
}

// syncLabels adds and removes labels in one request. GitLab creates a label the project does not
// have, and removing a label the issue no longer carries is not an error.
func (p gitlabIssuePublisher) syncLabels(ctx context.Context, item trackedItem, facts []string) error {
	var missing, stale []string
	for _, l := range append(append([]string(nil), p.item().Labels...), facts...) {
		if !containsFold(item.Labels, l) && !containsFold(missing, l) {
			missing = append(missing, l)
		}
	}
	for _, l := range item.Labels {
		if saga.IsFactLabel(l) && !containsFold(facts, l) {
			stale = append(stale, l)
		}
	}
	if len(missing) == 0 && len(stale) == 0 {
		return nil
	}
	req := map[string]string{}
	if len(missing) > 0 {
		req["add_labels"] = strings.Join(missing, ",")
	}
	if len(stale) > 0 {
		req["remove_labels"] = strings.Join(stale, ",")
	}
	_, err := p.do(ctx, "label #"+strconv.FormatInt(item.Number, 10), http.MethodPut, p.issueURL(item.Number), req, nil)
	return err
}

func (p gitlabIssuePublisher) comment(ctx context.Context, n int64, text string) error {
	_, err := p.do(ctx, "comment on #"+strconv.FormatInt(n, 10), http.MethodPost,
		p.issueURL(n)+"/notes", map[string]string{"body": text}, nil)
	return err
}

// close closes an issue. GitLab's REST API records no reason, so the comment posted before it is
// what says why.
func (p gitlabIssuePublisher) close(ctx context.Context, n int64, _ closeReason) error {
	_, err := p.do(ctx, "close #"+strconv.FormatInt(n, 10), http.MethodPut,
		p.issueURL(n), map[string]string{"state_event": "close"}, nil)
	return err
}

// member resolves a username to the user id an issue is assigned by, among the project's members,
// inherited ones included. The project's member list is what a token with Member: Read may read;
// the instance's user list needs a permission beyond it.
func (p gitlabIssuePublisher) member(ctx context.Context, username string) (int64, error) {
	q := url.Values{"query": {username}, "per_page": {"100"}}
	for page := "1"; page != ""; {
		q.Set("page", page)
		var members []struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		}
		h, err := p.do(ctx, "list members", http.MethodGet, p.projectURL("members/all")+"?"+q.Encode(), nil, &members)
		if err != nil {
			return 0, err
		}
		for _, m := range members {
			if strings.EqualFold(m.Username, username) {
				return m.ID, nil
			}
		}
		page = h.Get("X-Next-Page")
	}
	return 0, fmt.Errorf("gitlab-issue publisher: item.assignees %q is not a member of %s", username, p.project)
}

// milestone resolves a milestone's title to the id an issue takes, among the project's milestones
// and its groups', open or closed.
func (p gitlabIssuePublisher) milestone(ctx context.Context, title string) (int64, error) {
	q := url.Values{"title": {title}, "include_ancestors": {"true"}}
	var ms []struct {
		ID    int64  `json:"id"`
		Title string `json:"title"`
	}
	if _, err := p.do(ctx, "list milestones", http.MethodGet, p.projectURL("milestones")+"?"+q.Encode(), nil, &ms); err != nil {
		return 0, err
	}
	for _, m := range ms {
		if m.Title == title {
			return m.ID, nil
		}
	}
	return 0, fmt.Errorf("gitlab-issue publisher: item.milestone %q is not a milestone of %s or its groups, open or closed",
		title, p.project)
}

func (p gitlabIssuePublisher) item() saga.IssueItem {
	if p.cfg.Item == nil {
		return saga.IssueItem{}
	}
	return *p.cfg.Item
}

// confidential is whether a new issue is visible only to project members: true unless the entry
// says otherwise, because the body lists the findings.
func (p gitlabIssuePublisher) confidential() bool {
	return p.cfg.Item == nil || p.cfg.Item.Confidential == nil || *p.cfg.Item.Confidential
}

// projectURL is a path under the project. A project path holds slashes, which have to reach GitLab
// as %2F.
func (p gitlabIssuePublisher) projectURL(rest string) string {
	return p.apiURL + "/projects/" + url.PathEscape(p.project) + "/" + rest
}

func (p gitlabIssuePublisher) issueURL(n int64) string {
	return p.projectURL("issues/" + strconv.FormatInt(n, 10))
}

// gitlabStatusError is an answer GitLab gave that was not a success, worded for the reader who has
// to fix it.
type gitlabStatusError struct {
	status        int
	what, project string
	body          string
}

func (e *gitlabStatusError) Error() string {
	prefix := fmt.Sprintf("gitlab-issue publisher: %s in %s", e.what, e.project)
	switch e.status {
	case http.StatusUnauthorized:
		return prefix + ": 401, the token is not valid or has expired"
	case http.StatusForbidden:
		return prefix + ": 403, the token needs Work Item: Create, Read and Update, or the api scope, and its user " +
			"the Planner role; or issues are turned off for the project"
	case http.StatusNotFound:
		return prefix + ": 404, the project or item does not exist, or the token cannot see it"
	}
	return fmt.Sprintf("%s: %d: %s", prefix, e.status, e.body)
}

// do sends one request, decoding a success into out when out is not nil.
func (p gitlabIssuePublisher) do(ctx context.Context, what, method, target string, in, out any) (http.Header, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", p.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitlab-issue publisher: %s in %s: %w", what, p.project, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, &gitlabStatusError{status: resp.StatusCode, what: what, project: p.project,
			body: strings.TrimSpace(string(msg))}
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return nil, fmt.Errorf("gitlab-issue publisher: %s in %s: %w", what, p.project, err)
		}
	}
	return resp.Header, nil
}
