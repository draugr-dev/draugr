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
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// githubIssueBudget is the longest body written to a GitHub issue. GitHub documents no limit;
// 65,536 characters is the one widely reported, and the margin covers a count that differs.
const githubIssueBudget = 60_000

// githubIssuePublisher keeps one GitHub issue open for each failing part of the gate and closes it
// when that part passes. Repository and token come from the environment, as for the other GitHub
// kinds.
type githubIssuePublisher struct {
	cfg                 saga.PublisherConfig
	repo, token, apiURL string
	label               string
	client              *http.Client
}

func newGithubIssuePublisher(cfg saga.PublisherConfig) (Publisher, error) {
	tokenEnv := firstNonEmpty(cfg.TokenEnv, "GITHUB_TOKEN")
	p := githubIssuePublisher{
		cfg:    cfg,
		repo:   firstNonEmpty(cfg.Repo, os.Getenv("GITHUB_REPOSITORY")),
		token:  os.Getenv(tokenEnv),
		apiURL: strings.TrimSuffix(firstNonEmpty(os.Getenv("GITHUB_API_URL"), "https://api.github.com"), "/"),
		label:  firstNonEmpty(cfg.Label, defaultIssueLabel),
		client: newIssueClient(http.DefaultClient),
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" && cfg.Repo == "" && p.token == "" {
		return skipPublisher{kind: "github-issue", reason: "not a GitHub Actions environment"}, nil
	}
	var missing []string
	if p.repo == "" {
		missing = append(missing, "repo (or $GITHUB_REPOSITORY)")
	}
	if p.token == "" {
		missing = append(missing, "$"+tokenEnv+", mapped into the job's env from secrets.GITHUB_TOKEN or a token with Issues: write")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("github-issue publisher missing: %s", strings.Join(missing, "; "))
	}
	return p, nil
}

func (githubIssuePublisher) Kind() string { return "github-issue" }

// Publish is never the path a run takes, since Run calls PublishRun. Without the run there is no
// gate to follow, so it refuses rather than doing nothing.
func (githubIssuePublisher) Publish(context.Context, []report.Artifact) error {
	return errors.New("github-issue publisher follows the gate, and needs the run: call PublishRun")
}

// PublishRun opens, rewrites and closes the entry's issues to match the run.
func (p githubIssuePublisher) PublishRun(ctx context.Context, data report.Data, _ []report.Artifact) error {
	return trackIssues(ctx, p, data, p.cfg)
}

func (githubIssuePublisher) kind() string        { return "github-issue" }
func (githubIssuePublisher) format() issueFormat { return markdownFormat{} }
func (githubIssuePublisher) budget() int         { return githubIssueBudget }
func (githubIssuePublisher) ref(n int64) string  { return "#" + strconv.FormatInt(n, 10) }

// childWrites is the issue and its sub-issue link.
func (githubIssuePublisher) childWrites() int          { return 2 }
func (p githubIssuePublisher) affords(writes int) bool { return clientAffords(p.client, writes) }

type githubIssue struct {
	ID     int64  `json:"id"`
	Number int64  `json:"number"`
	Body   string `json:"body"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Assignees []struct {
		Login string `json:"login"`
	} `json:"assignees"`
	Milestone *struct {
		Number int64 `json:"number"`
	} `json:"milestone"`
	Type *struct {
		Name string `json:"name"`
	} `json:"type"`
	PullRequest json.RawMessage `json:"pull_request"`
}

func (i githubIssue) labelNames() []string {
	out := make([]string, len(i.Labels))
	for j, l := range i.Labels {
		out[j] = l.Name
	}
	return out
}

// open lists the open issues carrying the tracking label, oldest first. The issues endpoint
// returns pull requests too, which are left out.
func (p githubIssuePublisher) open(ctx context.Context) ([]trackedItem, error) {
	q := url.Values{"labels": {p.label}, "state": {"open"}, "sort": {"created"}, "direction": {"asc"}, "per_page": {"100"}}
	next := p.repoURL("issues") + "?" + q.Encode()
	var out []trackedItem
	for next != "" {
		var page []githubIssue
		h, err := p.do(ctx, "list issues", http.MethodGet, next, nil, &page)
		if err != nil {
			return nil, err
		}
		for _, i := range page {
			if len(i.PullRequest) > 0 && string(i.PullRequest) != "null" {
				continue
			}
			out = append(out, trackedItem{Number: i.Number, Body: i.Body, Labels: i.labelNames()})
		}
		next = nextPageURL(h.Get("Link"))
	}
	return out, nil
}

// create opens an issue with the tracking label, the configured metadata and the fact labels, then
// checks that GitHub kept the metadata. GitHub drops labels, assignees, a milestone and a type
// without an error when the token cannot set them.
//
// A child is linked to its parent as a sub-issue, and takes no type: the configured one describes
// the parent.
func (p githubIssuePublisher) create(ctx context.Context, title, body string, facts []string, parent *trackedItem) (trackedItem, error) {
	got, err := p.createIssue(ctx, title, body, facts, parent == nil)
	if err != nil || parent == nil {
		return got, err
	}
	n := strconv.FormatInt(parent.Number, 10)
	_, err = p.do(ctx, "link #"+strconv.FormatInt(got.Number, 10)+" to #"+n, http.MethodPost,
		p.repoURL("issues/"+n+"/sub_issues"), map[string]int64{"sub_issue_id": got.ID}, nil)
	if err == nil {
		return got, nil
	}
	if isStatus(err, http.StatusNotFound) {
		err = fmt.Errorf("%w. Sub-issues need GitHub.com or GitHub Enterprise Server 3.18 or later", err)
	}
	// A child that is not linked is an issue nobody will find from its parent, and the next run
	// would not know to link it.
	_ = p.close(ctx, got.Number, closedUntracked)
	return trackedItem{}, err
}

func (p githubIssuePublisher) createIssue(ctx context.Context, title, body string, facts []string, typed bool) (trackedItem, error) {
	item := p.item()
	if !typed {
		item.Type = ""
	}
	var labels []string
	for _, l := range append(append([]string{p.label}, item.Labels...), facts...) {
		if !containsFold(labels, l) {
			labels = append(labels, l)
		}
	}
	for _, l := range labels {
		if err := p.ensureLabel(ctx, l); err != nil {
			return trackedItem{}, err
		}
	}
	req := map[string]any{"title": title, "body": body, "labels": labels}
	if len(item.Assignees) > 0 {
		req["assignees"] = item.Assignees
	}
	var milestone int64
	if item.Milestone != "" {
		n, err := p.milestone(ctx, item.Milestone)
		if err != nil {
			return trackedItem{}, err
		}
		milestone = n
		req["milestone"] = n
	}
	if item.Type != "" {
		req["type"] = item.Type
	}
	var got githubIssue
	if _, err := p.do(ctx, "create an issue", http.MethodPost, p.repoURL("issues"), req, &got); err != nil {
		return trackedItem{}, err
	}

	var dropped []string
	for _, l := range labels {
		if !containsFold(got.labelNames(), l) {
			dropped = append(dropped, "label "+l)
		}
	}
	for _, a := range item.Assignees {
		found := false
		for _, g := range got.Assignees {
			found = found || strings.EqualFold(g.Login, a)
		}
		if !found {
			dropped = append(dropped, "assignee "+a)
		}
	}
	if milestone != 0 && (got.Milestone == nil || got.Milestone.Number != milestone) {
		dropped = append(dropped, "milestone "+item.Milestone)
	}
	if item.Type != "" && (got.Type == nil || !strings.EqualFold(got.Type.Name, item.Type)) {
		dropped = append(dropped, "type "+item.Type)
	}
	if len(dropped) > 0 {
		return trackedItem{}, fmt.Errorf("github-issue publisher: created #%d in %s without %s. GitHub drops these "+
			"without an error when the token has no push access to the repository, or an assignee "+
			"cannot be assigned", got.Number, p.repo, strings.Join(dropped, ", "))
	}
	return trackedItem{Number: got.Number, ID: got.ID, Body: body, Labels: got.labelNames()}, nil
}

func (p githubIssuePublisher) rewrite(ctx context.Context, n int64, body string) error {
	_, err := p.do(ctx, "update #"+strconv.FormatInt(n, 10), http.MethodPatch,
		p.repoURL("issues/"+strconv.FormatInt(n, 10)), map[string]string{"body": body}, nil)
	return err
}

func (p githubIssuePublisher) retitle(ctx context.Context, n int64, title string) error {
	_, err := p.do(ctx, "retitle #"+strconv.FormatInt(n, 10), http.MethodPatch,
		p.repoURL("issues/"+strconv.FormatInt(n, 10)), map[string]string{"title": title}, nil)
	return err
}

func (p githubIssuePublisher) syncLabels(ctx context.Context, item trackedItem, facts []string) error {
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
	n := strconv.FormatInt(item.Number, 10)
	if len(missing) > 0 {
		for _, l := range missing {
			if err := p.ensureLabel(ctx, l); err != nil {
				return err
			}
		}
		if _, err := p.do(ctx, "label #"+n, http.MethodPost,
			p.repoURL("issues/"+n+"/labels"), map[string][]string{"labels": missing}, nil); err != nil {
			return err
		}
	}
	for _, l := range stale {
		// A 404 is a label somebody removed since the issue was read, which is the state wanted.
		_, err := p.do(ctx, "remove label "+l+" from #"+n, http.MethodDelete,
			p.repoURL("issues/"+n+"/labels/"+url.PathEscape(l)), nil, nil)
		if err != nil && !isStatus(err, http.StatusNotFound) {
			return err
		}
	}
	return nil
}

func (p githubIssuePublisher) comment(ctx context.Context, n int64, text string) error {
	_, err := p.do(ctx, "comment on #"+strconv.FormatInt(n, 10), http.MethodPost,
		p.repoURL("issues/"+strconv.FormatInt(n, 10)+"/comments"), map[string]string{"body": text}, nil)
	return err
}

func (p githubIssuePublisher) close(ctx context.Context, n int64, reason closeReason) error {
	stateReason := map[closeReason]string{
		closedPassing:   "completed",
		closedDuplicate: "duplicate",
		closedUntracked: "not_planned",
	}[reason]
	_, err := p.do(ctx, "close #"+strconv.FormatInt(n, 10), http.MethodPatch,
		p.repoURL("issues/"+strconv.FormatInt(n, 10)), map[string]string{"state": "closed", "state_reason": stateReason}, nil)
	return err
}

// ensureLabel creates a label the repository does not have. GitHub does not document creating one
// from an issue's labels, and without push access it drops the label instead.
func (p githubIssuePublisher) ensureLabel(ctx context.Context, name string) error {
	at := p.repoURL("labels/" + url.PathEscape(name))
	_, err := p.do(ctx, "read label "+name, http.MethodGet, at, nil, nil)
	if !isStatus(err, http.StatusNotFound) {
		return err
	}
	color, description := labelStyle(name)
	req := map[string]string{"name": name, "color": color}
	if description != "" {
		req["description"] = description
	}
	_, err = p.do(ctx, "create label "+name, http.MethodPost, p.repoURL("labels"), req, nil)
	// Another run creating the same label answers 422, which GitHub does not document as meaning
	// that. The label is read again rather than trusted to exist.
	if isStatus(err, http.StatusUnprocessableEntity) {
		_, err = p.do(ctx, "read label "+name, http.MethodGet, at, nil, nil)
	}
	return err
}

// labelStyle is the color and description a label is created with. A fact label says what it
// carries, for the reader who meets it without having configured it; a configured label is the
// tracking color with no description.
func labelStyle(name string) (color, description string) {
	if !saga.IsFactLabel(name) {
		return "b60205", ""
	}
	fact, value, _ := strings.Cut(strings.TrimPrefix(strings.ToLower(name), "draugr:"), ":")
	switch fact {
	case saga.LabelByPriority:
		color = map[string]string{"p1": "b60205", "p2": "d93f0b", "p3": "fbca04"}[value]
		if color == "" {
			color = "c5def5"
		}
		return color, "The highest priority among the findings the issue lists. Kept by Draugr."
	case saga.LabelByControl:
		return "1d76db", "A control with a finding the issue lists. Kept by Draugr."
	case saga.LabelByExposure:
		return "5319e7", "An exposure of a component with a finding the issue lists. Kept by Draugr."
	case saga.LabelByCriticality:
		return "5319e7", "A criticality of a component with a finding the issue lists. Kept by Draugr."
	default:
		return "e99695", "A scan error stops a control the issue covers. Kept by Draugr."
	}
}

// milestone resolves a milestone's title to the number an issue takes.
func (p githubIssuePublisher) milestone(ctx context.Context, title string) (int64, error) {
	next := p.repoURL("milestones") + "?state=all&per_page=100"
	for next != "" {
		var page []struct {
			Number int64  `json:"number"`
			Title  string `json:"title"`
		}
		h, err := p.do(ctx, "list milestones", http.MethodGet, next, nil, &page)
		if err != nil {
			return 0, err
		}
		for _, m := range page {
			if m.Title == title {
				return m.Number, nil
			}
		}
		next = nextPageURL(h.Get("Link"))
	}
	return 0, fmt.Errorf("github-issue publisher: item.milestone %q is not a milestone of %s, open or closed", title, p.repo)
}

func (p githubIssuePublisher) item() saga.IssueItem {
	if p.cfg.Item == nil {
		return saga.IssueItem{}
	}
	return *p.cfg.Item
}

func (p githubIssuePublisher) repoURL(rest string) string {
	return p.apiURL + "/repos/" + p.repo + "/" + rest
}

// githubStatusError is an answer GitHub gave that was not a success, worded for the reader who has
// to fix it.
type githubStatusError struct {
	status      int
	what, repo  string
	permissions string
	body        string
}

func (e *githubStatusError) Error() string {
	prefix := fmt.Sprintf("github-issue publisher: %s in %s", e.what, e.repo)
	switch e.status {
	case http.StatusForbidden:
		if e.permissions != "" {
			return fmt.Sprintf("%s: 403, the token needs %s. For GITHUB_TOKEN, grant it in the "+
				"workflow with `permissions: issues: write`", prefix, e.permissions)
		}
	case http.StatusGone:
		return prefix + ": 410, issues are turned off for the repository"
	case http.StatusNotFound:
		return prefix + ": 404, the repository or item does not exist, or the token cannot see it"
	case http.StatusUnprocessableEntity:
		if why := validationMessages(e.body); why != "" {
			return fmt.Sprintf("%s: 422, %s", prefix, why)
		}
	}
	return fmt.Sprintf("%s: %d: %s", prefix, e.status, e.body)
}

// validationMessages is what a 422 says about each field GitHub refused, such as an assignee who
// cannot be assigned, joined; empty when the body carries none.
func validationMessages(body string) string {
	var v struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal([]byte(body), &v) != nil {
		return ""
	}
	var out []string
	for _, e := range v.Errors {
		if e.Message != "" {
			out = append(out, e.Message)
		}
	}
	return strings.Join(out, "; ")
}

func isStatus(err error, status int) bool {
	var se *githubStatusError
	return errors.As(err, &se) && se.status == status
}

// do sends one request, decoding a success into out when out is not nil.
func (p githubIssuePublisher) do(ctx context.Context, what, method, target string, in, out any) (http.Header, error) {
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
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github-issue publisher: %s in %s: %w", what, p.repo, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, &githubStatusError{
			status:      resp.StatusCode,
			what:        what,
			repo:        p.repo,
			permissions: resp.Header.Get("X-Accepted-GitHub-Permissions"),
			body:        strings.TrimSpace(string(msg)),
		}
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return nil, fmt.Errorf("github-issue publisher: %s in %s: %w", what, p.repo, err)
		}
	}
	return resp.Header, nil
}

func containsFold(values []string, v string) bool {
	for _, x := range values {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
