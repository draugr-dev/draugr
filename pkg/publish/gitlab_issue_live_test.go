//go:build integration

package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The project the live test writes issues to, as a path or an id, and a token that may write them.
// The project should be one nobody reads: every run opens and closes issues in it.
//
// #nosec G101 -- the names of environment variables, not their values.
const (
	liveGitLabTokenEnv   = "SANDBOX_GITLAB_TOKEN"
	liveGitLabProjectEnv = "SANDBOX_GITLAB_PROJECT"
)

// liveGitLabAPI is gitlab.com's API root, where the sandbox project lives.
const liveGitLabAPI = "https://gitlab.com/api/v4/"

// liveGitLab is the sandbox project, read and written with GitLab's own API rather than through
// the publisher, so what the test asserts is what GitLab holds.
type liveGitLab struct {
	t              *testing.T
	project, token string
	name           string
	run            int
}

type liveGitLabIssue struct {
	ID           int64    `json:"id"`
	IID          int64    `json:"iid"`
	Title        string   `json:"title"`
	State        string   `json:"state"`
	Description  string   `json:"description"`
	UpdatedAt    string   `json:"updated_at"`
	Labels       []string `json:"labels"`
	IssueType    string   `json:"issue_type"`
	Confidential bool     `json:"confidential"`
	Assignees    []struct {
		Username string `json:"username"`
	} `json:"assignees"`
}

// newLiveGitLab skips unless a sandbox project and a token for it are configured. Each test names
// its own Draugr project, so its markers match no issue another run or another test left open.
func newLiveGitLab(t *testing.T) *liveGitLab {
	t.Helper()
	token, project := os.Getenv(liveGitLabTokenEnv), os.Getenv(liveGitLabProjectEnv)
	if token == "" || project == "" {
		t.Skipf("set %s and %s to drive the gitlab-issue publisher against a real project", liveGitLabTokenEnv, liveGitLabProjectEnv)
	}
	g := &liveGitLab{t: t, project: project, token: token,
		name: fmt.Sprintf("live-%s-%d", strings.ToLower(t.Name()), time.Now().UnixNano())}
	t.Cleanup(g.closeLeftovers)
	return g
}

func (g *liveGitLab) api(method, path string, body, out any) {
	g.t.Helper()
	r := bytes.NewReader(nil)
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			g.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	target := liveGitLabAPI + "projects/" + url.PathEscape(g.project) + "/" + path
	req, err := http.NewRequestWithContext(context.Background(), method, target, r)
	if err != nil {
		g.t.Fatal(err)
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		g.t.Fatalf("%s %s: %s", method, path, resp.Status)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			g.t.Fatal(err)
		}
	}
}

// open lists this test's open issues, oldest first, with the query the publisher sends.
func (g *liveGitLab) open() []liveGitLabIssue {
	g.t.Helper()
	q := url.Values{"labels": {liveLabel}, "state": {"opened"}, "order_by": {"created_at"}, "sort": {"asc"}, "per_page": {"100"}}
	var all, mine []liveGitLabIssue
	g.api(http.MethodGet, "issues?"+q.Encode(), nil, &all)
	for _, i := range all {
		if strings.Contains(i.Description, "project="+g.name+" ") {
			mine = append(mine, i)
		}
	}
	return mine
}

// openCount polls until n issues are open. GitLab's list can trail a write, and a run that reads
// it early misses the issue it just opened.
func (g *liveGitLab) openCount(n int) []liveGitLabIssue {
	g.t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		open := g.open()
		if len(open) == n {
			return open
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("the open issues never numbered %d: %d open", n, len(open))
		}
		time.Sleep(3 * time.Second)
	}
}

func (g *liveGitLab) issue(n int64) liveGitLabIssue {
	g.t.Helper()
	var i liveGitLabIssue
	g.api(http.MethodGet, "issues/"+strconv.FormatInt(n, 10), nil, &i)
	return i
}

// notes are the comments on an issue, oldest first, without the system notes GitLab adds for every
// change of label, description or state.
func (g *liveGitLab) notes(n int64) []string {
	g.t.Helper()
	var ns []struct {
		Body   string `json:"body"`
		System bool   `json:"system"`
	}
	g.api(http.MethodGet, "issues/"+strconv.FormatInt(n, 10)+"/notes?sort=asc&per_page=100", nil, &ns)
	var out []string
	for _, n := range ns {
		if !n.System {
			out = append(out, n.Body)
		}
	}
	return out
}

// member is a username the project's members list holds, so an assignee the publisher resolves.
func (g *liveGitLab) member() string {
	g.t.Helper()
	var ms []struct {
		Username string `json:"username"`
	}
	g.api(http.MethodGet, "members/all?per_page=1", nil, &ms)
	if len(ms) == 0 {
		g.t.Fatal("the sandbox project lists no members")
	}
	return ms[0].Username
}

// closeLeftovers closes whatever this test left open, so a failed run does not leave the next one
// reading its issues.
func (g *liveGitLab) closeLeftovers() {
	for _, i := range g.open() {
		g.api(http.MethodPut, "issues/"+strconv.FormatInt(i.IID, 10), map[string]string{"state_event": "close"}, nil)
	}
}

// publisher is the gitlab-issue publisher as a GitLab CI job would build it, against the sandbox.
func (g *liveGitLab) publisher(cfg saga.PublisherConfig) gitlabIssuePublisher {
	g.t.Helper()
	g.t.Setenv("GITLAB_CI", "true")
	g.t.Setenv("CI_API_V4_URL", strings.TrimSuffix(liveGitLabAPI, "/"))
	g.t.Setenv("CI_PROJECT_ID", g.project)
	g.t.Setenv("GITLAB_TOKEN", g.token)
	cfg.Kind = "gitlab-issue"
	cfg.Label = liveLabel
	p, err := For(cfg)
	if err != nil {
		g.t.Fatal(err)
	}
	gp, ok := p.(gitlabIssuePublisher)
	if !ok {
		g.t.Fatalf("publisher is %T", p)
	}
	return gp
}

// onMain is a run of this test's project on the default branch, in a job numbered by how many runs
// the test has made.
func (g *liveGitLab) onMain(controls map[string][]sarif.Result) report.Data {
	g.run++
	d := runOver(controls)
	d.Project = g.name
	id := strconv.Itoa(g.run)
	d.CI = &ci.Context{Branch: "main", DefaultBranch: "main", RunID: id,
		URL: "https://gitlab.com/" + g.project + "/-/pipelines/" + id}
	return d
}

func (g *liveGitLab) mustPublish(p gitlabIssuePublisher, data report.Data) {
	g.t.Helper()
	if err := p.PublishRun(context.Background(), data, nil); err != nil {
		g.t.Fatal(err)
	}
}

func (g *liveGitLab) jobText(verb string) string {
	id := strconv.Itoa(g.run)
	return verb + " on `main` in [job " + id + "](https://gitlab.com/" + g.project + "/-/pipelines/" + id + ")."
}

// TestLiveGitLabIssueLifecycle takes one issue through everything a run can do to it, against a real
// project: open it confidential with its metadata, leave it alone, rewrite it, restore a label
// removed by hand, close a duplicate somebody opened, ignore a merge request, and close it when the
// gate passes.
//
// The fake in gitlab_issue_test.go answers the way GitLab is documented to. This is the check that
// GitLab still answers that way, and that the token the docs describe is enough: that it creates
// the labels an issue names, keeps a type, an assignee and confidentiality, and lets the token's
// user comment and close. The type is task because the sandbox's user holds Planner, and an
// incident needs Reporter.
func TestLiveGitLabIssueLifecycle(t *testing.T) {
	g := newLiveGitLab(t)
	assignee := g.member()
	p := g.publisher(saga.PublisherConfig{Item: &saga.IssueItem{
		Labels: []string{"triage"}, Assignees: []string{assignee}, Type: "task",
	}})

	failing := map[string][]sarif.Result{"sca": {upgradeFinding("api", "CVE-2026-0001", "P1")}}
	g.mustPublish(p, g.onMain(failing))
	first := g.openCount(1)[0]
	for _, want := range []string{liveLabel, "triage", "draugr:priority:P1"} {
		if !slices.Contains(first.Labels, want) {
			t.Errorf("labels = %q, want %s", first.Labels, want)
		}
	}
	if first.IssueType != "task" {
		t.Errorf("type = %q, want task", first.IssueType)
	}
	if !first.Confidential {
		t.Error("a new issue is not confidential")
	}
	if len(first.Assignees) != 1 || first.Assignees[0].Username != assignee {
		t.Errorf("assignees = %+v, want %s", first.Assignees, assignee)
	}

	// The same findings again: the body names the run that last changed it, so nothing is written.
	g.mustPublish(p, g.onMain(failing))
	if again := g.issue(first.IID); again.UpdatedAt != first.UpdatedAt || again.Description != first.Description {
		t.Errorf("an unchanged run rewrote #%d (updated %s, was %s)", first.IID, again.UpdatedAt, first.UpdatedAt)
	}

	// Another finding: the body is rewritten in place, and nobody gets a comment.
	failing["sast"] = []sarif.Result{codeFinding("api", "python.lang.eval", "P1", "app/app.py")}
	g.mustPublish(p, g.onMain(failing))
	rewritten := g.issue(first.IID)
	if rewritten.Description == first.Description || !strings.Contains(rewritten.Description, "python.lang.eval") {
		t.Errorf("#%d was not rewritten with the new finding", first.IID)
	}
	if ns := g.notes(first.IID); len(ns) != 0 {
		t.Errorf("a rewrite commented on #%d: %q", first.IID, ns)
	}

	// A fact label removed by hand comes back; the tracking label is what finds the issue, so it
	// stays on.
	g.api(http.MethodPut, "issues/"+strconv.FormatInt(first.IID, 10), map[string]string{"remove_labels": "draugr:priority:P1"}, nil)
	g.mustPublish(p, g.onMain(failing))
	if i := g.issue(first.IID); !slices.Contains(i.Labels, "draugr:priority:P1") {
		t.Errorf("after triage: labels %q, want draugr:priority:P1 back", i.Labels)
	}

	// Somebody opens a second issue carrying the same marker. The newer one closes against the older.
	var dup liveGitLabIssue
	g.api(http.MethodPost, "issues", map[string]any{"title": "copy", "description": rewritten.Description, "labels": liveLabel}, &dup)
	g.openCount(2)
	g.mustPublish(p, g.onMain(failing))
	if i := g.issue(dup.IID); i.State != "closed" {
		t.Errorf("duplicate #%d = %s, want closed", dup.IID, i.State)
	}
	if ns := g.notes(dup.IID); len(ns) != 1 || ns[0] != fmt.Sprintf("Duplicate of #%d.", first.IID) {
		t.Errorf("duplicate notes = %q", ns)
	}

	g.openCount(1)

	// A merge request that fixes everything is judged on changes nobody has merged.
	mr := g.onMain(map[string][]sarif.Result{"sca": nil})
	mr.CI.PullRequest = true
	g.mustPublish(p, mr)
	if i := g.issue(first.IID); i.State != "opened" {
		t.Errorf("a merge-request run closed #%d", first.IID)
	}

	g.mustPublish(p, g.onMain(map[string][]sarif.Result{"sca": nil}))
	if i := g.issue(first.IID); i.State != "closed" {
		t.Errorf("#%d = %s, want closed", first.IID, i.State)
	}
	if ns := g.notes(first.IID); len(ns) != 1 || ns[0] != g.jobText("The gate passes") {
		t.Errorf("closing notes = %q, want %q", ns, g.jobText("The gate passes"))
	}
}

// TestLiveGitLabUnknownAssigneeIsNamed asks for an assignee who is not a member of the project. The
// run names the username before it writes anything.
func TestLiveGitLabUnknownAssigneeIsNamed(t *testing.T) {
	g := newLiveGitLab(t)
	nobody := "draugr-no-such-member-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	p := g.publisher(saga.PublisherConfig{Item: &saga.IssueItem{Assignees: []string{nobody}}})
	err := p.PublishRun(context.Background(), g.onMain(map[string][]sarif.Result{"sca": {upgradeFinding("api", "CVE-2026-0001", "P1")}}), nil)
	if err == nil || !strings.Contains(err.Error(), nobody) {
		t.Fatalf("err = %v, want it to name %s", err, nobody)
	}
	if n := len(g.open()); n != 0 {
		t.Errorf("open issues = %d, want none", n)
	}
}
