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

// The repository the live test writes issues to, and a token that may write them. The repository
// should be one nobody reads: every run opens and closes issues in it.
//
// #nosec G101 -- the names of environment variables, not their values.
const (
	liveGitHubTokenEnv = "SANDBOX_GITHUB_TOKEN"
	liveGitHubRepoEnv  = "SANDBOX_GITHUB_REPO"
)

// liveLabel finds the live test's issues, apart from anything else the repository holds.
const liveLabel = "draugr-live"

// liveMilestone is the milestone the live test sets on a new issue, created when it is missing.
const liveMilestone = "Live test"

// liveGitHub is the sandbox repository, read and written with GitHub's own API rather than through
// the publisher, so what the test asserts is what GitHub holds.
type liveGitHub struct {
	t           *testing.T
	repo, token string
	project     string
	run         int
}

type liveIssue struct {
	Number      int64  `json:"number"`
	State       string `json:"state"`
	StateReason string `json:"state_reason"`
	Body        string `json:"body"`
	UpdatedAt   string `json:"updated_at"`
	Comments    int    `json:"comments"`
	Labels      []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Milestone *struct {
		Title string `json:"title"`
	} `json:"milestone"`
	Type *struct {
		Name string `json:"name"`
	} `json:"type"`
}

func (i liveIssue) hasLabel(name string) bool {
	return slices.ContainsFunc(i.Labels, func(l struct {
		Name string `json:"name"`
	}) bool {
		return l.Name == name
	})
}

// newLiveGitHub skips unless a sandbox repository and a token for it are configured. Each test
// names its own project, so its markers match no issue another run or another test left open.
func newLiveGitHub(t *testing.T) *liveGitHub {
	t.Helper()
	token, repo := os.Getenv(liveGitHubTokenEnv), os.Getenv(liveGitHubRepoEnv)
	if token == "" || repo == "" {
		t.Skipf("set %s and %s to drive the github-issue publisher against a real repository", liveGitHubTokenEnv, liveGitHubRepoEnv)
	}
	g := &liveGitHub{t: t, repo: repo, token: token,
		project: fmt.Sprintf("live-%s-%d", strings.ToLower(t.Name()), time.Now().UnixNano())}
	t.Cleanup(g.closeLeftovers)
	return g
}

func (g *liveGitHub) api(method, path string, body, out any) {
	g.t.Helper()
	var r *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			g.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, "https://api.github.com/repos/"+g.repo+"/"+path, r)
	if err != nil {
		g.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
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

// open lists this test's open issues, oldest first, with the query the publisher sends. GitHub
// answers each query from its own view, and another query can show a close this one does not yet.
func (g *liveGitHub) open() []liveIssue {
	g.t.Helper()
	q := url.Values{"labels": {liveLabel}, "state": {"open"}, "sort": {"created"}, "direction": {"asc"}, "per_page": {"100"}}
	var all, mine []liveIssue
	g.api(http.MethodGet, "issues?"+q.Encode(), nil, &all)
	for _, i := range all {
		if strings.Contains(i.Body, "project="+g.project+" ") {
			mine = append(mine, i)
		}
	}
	return mine
}

// until polls the open issues until cond holds of them. GitHub's list trails a write by seconds,
// and a run that reads it early misses the issue it just opened, so each step waits for the list to
// show the last one before the next run reads it.
func (g *liveGitHub) until(what string, cond func([]liveIssue) bool) []liveIssue {
	g.t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		open := g.open()
		if cond(open) {
			return open
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("the open issues never showed %s: %d open", what, len(open))
		}
		time.Sleep(3 * time.Second)
	}
}

// openCount waits until n issues are open.
func (g *liveGitHub) openCount(n int) []liveIssue {
	g.t.Helper()
	return g.until(fmt.Sprintf("%d open", n), func(open []liveIssue) bool { return len(open) == n })
}

func (g *liveGitHub) issue(n int64) liveIssue {
	g.t.Helper()
	var i liveIssue
	g.api(http.MethodGet, "issues/"+strconv.FormatInt(n, 10), nil, &i)
	return i
}

func (g *liveGitHub) comments(n int64) []string {
	g.t.Helper()
	var cs []struct {
		Body string `json:"body"`
	}
	g.api(http.MethodGet, "issues/"+strconv.FormatInt(n, 10)+"/comments", nil, &cs)
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Body
	}
	return out
}

// ensureMilestone creates the live test's milestone when the repository does not have it.
func (g *liveGitHub) ensureMilestone() {
	g.t.Helper()
	var ms []struct {
		Title string `json:"title"`
	}
	g.api(http.MethodGet, "milestones?state=all&per_page=100", nil, &ms)
	for _, m := range ms {
		if m.Title == liveMilestone {
			return
		}
	}
	g.api(http.MethodPost, "milestones", map[string]string{"title": liveMilestone}, nil)
}

// closeLeftovers closes whatever this test left open, so a failed run does not leave the next one
// reading its issues.
func (g *liveGitHub) closeLeftovers() {
	for _, i := range g.open() {
		g.api(http.MethodPatch, "issues/"+strconv.FormatInt(i.Number, 10), map[string]string{"state": "closed"}, nil)
	}
}

// publisher is the github-issue publisher as a GitHub Actions job would build it, against the
// sandbox, with the client's real pacing.
func (g *liveGitHub) publisher(cfg saga.PublisherConfig) githubIssuePublisher {
	g.t.Helper()
	g.t.Setenv("GITHUB_ACTIONS", "true")
	g.t.Setenv("GITHUB_API_URL", "https://api.github.com")
	g.t.Setenv("GITHUB_REPOSITORY", g.repo)
	g.t.Setenv("GITHUB_TOKEN", g.token)
	cfg.Kind = "github-issue"
	cfg.Label = liveLabel
	p, err := For(cfg)
	if err != nil {
		g.t.Fatal(err)
	}
	gp, ok := p.(githubIssuePublisher)
	if !ok {
		g.t.Fatalf("publisher is %T", p)
	}
	return gp
}

// onMain is a run of this test's project on the default branch, in a job numbered by how many runs
// the test has made.
func (g *liveGitHub) onMain(controls map[string][]sarif.Result) report.Data {
	g.run++
	d := runOver(controls)
	d.Project = g.project
	id := strconv.Itoa(g.run)
	d.CI = &ci.Context{Branch: "main", DefaultBranch: "main", RunID: id,
		URL: "https://github.com/" + g.repo + "/actions/runs/" + id}
	return d
}

func (g *liveGitHub) publish(p githubIssuePublisher, data report.Data) error {
	return p.PublishRun(context.Background(), data, nil)
}

func (g *liveGitHub) mustPublish(p githubIssuePublisher, data report.Data) {
	g.t.Helper()
	if err := g.publish(p, data); err != nil {
		g.t.Fatal(err)
	}
}

func (g *liveGitHub) jobText(verb string) string {
	id := strconv.Itoa(g.run)
	return verb + " on `main` in [job " + id + "](https://github.com/" + g.repo + "/actions/runs/" + id + ")."
}

// TestLiveGitHubIssueLifecycle takes one issue through everything a run can do to it, against a real
// repository: open it with its metadata, leave it alone, rewrite it, restore a label removed by
// hand, close a duplicate somebody opened, ignore a pull request, and close it when the gate passes.
//
// The fake in github_issue_test.go answers the way GitHub is documented to. This is the check that
// GitHub still answers that way: that it keeps a type and a milestone, takes a duplicate state
// reason, and returns an issue it was just sent from the list that finds it.
func TestLiveGitHubIssueLifecycle(t *testing.T) {
	g := newLiveGitHub(t)
	g.ensureMilestone()
	p := g.publisher(saga.PublisherConfig{Item: &saga.IssueItem{
		Labels: []string{"triage"}, Milestone: liveMilestone, Type: "Bug",
	}})

	failing := map[string][]sarif.Result{"sca": {upgradeFinding("api", "CVE-2026-0001", "P1")}}
	g.mustPublish(p, g.onMain(failing))
	first := g.openCount(1)[0]
	if !first.hasLabel(liveLabel) || !first.hasLabel("triage") {
		t.Errorf("labels = %+v, want %s and triage", first.Labels, liveLabel)
	}
	if first.Type == nil || first.Type.Name != "Bug" {
		t.Errorf("type = %+v, want Bug", first.Type)
	}
	if first.Milestone == nil || first.Milestone.Title != liveMilestone {
		t.Errorf("milestone = %+v, want %s", first.Milestone, liveMilestone)
	}

	// The same findings again: the body names the run that last changed it, so nothing is written.
	g.mustPublish(p, g.onMain(failing))
	if again := g.issue(first.Number); again.UpdatedAt != first.UpdatedAt || again.Body != first.Body {
		t.Errorf("an unchanged run rewrote #%d (updated %s, was %s)", first.Number, again.UpdatedAt, first.UpdatedAt)
	}

	// Another finding: the body is rewritten in place, and nobody gets a comment.
	failing["sast"] = []sarif.Result{codeFinding("api", "python.lang.eval", "P1", "app/app.py")}
	g.mustPublish(p, g.onMain(failing))
	rewritten := g.issue(first.Number)
	if rewritten.Body == first.Body || !strings.Contains(rewritten.Body, "python.lang.eval") {
		t.Errorf("#%d was not rewritten with the new finding", first.Number)
	}
	if rewritten.Comments != 0 {
		t.Errorf("a rewrite commented on #%d", first.Number)
	}

	// A label removed by hand comes back; the milestone somebody moved stays where they put it.
	g.api(http.MethodDelete, "issues/"+strconv.FormatInt(first.Number, 10)+"/labels/triage", nil, nil)
	g.api(http.MethodPatch, "issues/"+strconv.FormatInt(first.Number, 10), map[string]any{"milestone": nil}, nil)
	g.until("#"+strconv.FormatInt(first.Number, 10)+" without triage", func(open []liveIssue) bool {
		return len(open) == 1 && !open[0].hasLabel("triage")
	})
	g.mustPublish(p, g.onMain(failing))
	if i := g.issue(first.Number); !i.hasLabel("triage") || i.Milestone != nil {
		t.Errorf("after triage: labels %+v, milestone %+v; want triage back and no milestone", i.Labels, i.Milestone)
	}

	// Somebody opens a second issue carrying the same marker. The newer one closes against the older.
	var dup liveIssue
	g.api(http.MethodPost, "issues", map[string]any{"title": "copy", "body": rewritten.Body, "labels": []string{liveLabel}}, &dup)
	g.openCount(2)
	g.mustPublish(p, g.onMain(failing))
	closedDup := g.issue(dup.Number)
	if closedDup.State != "closed" || closedDup.StateReason != "duplicate" {
		t.Errorf("duplicate #%d = %s/%s, want closed/duplicate", dup.Number, closedDup.State, closedDup.StateReason)
	}
	if cs := g.comments(dup.Number); len(cs) != 1 || cs[0] != fmt.Sprintf("Duplicate of #%d.", first.Number) {
		t.Errorf("duplicate comments = %q", cs)
	}

	g.openCount(1)

	// A pull request that fixes everything is judged on changes nobody has merged.
	pr := g.onMain(map[string][]sarif.Result{"sca": nil})
	pr.CI.PullRequest = true
	g.mustPublish(p, pr)
	if i := g.issue(first.Number); i.State != "open" {
		t.Errorf("a pull-request run closed #%d", first.Number)
	}

	g.mustPublish(p, g.onMain(map[string][]sarif.Result{"sca": nil}))
	closed := g.issue(first.Number)
	if closed.State != "closed" || closed.StateReason != "completed" {
		t.Errorf("#%d = %s/%s, want closed/completed", first.Number, closed.State, closed.StateReason)
	}
	if cs := g.comments(first.Number); len(cs) != 1 || cs[0] != g.jobText("The gate passes") {
		t.Errorf("closing comments = %q, want %q", cs, g.jobText("The gate passes"))
	}
}

// TestLiveGitHubIssueSplitAndMinimum is the two ways a part stops failing without the gate passing:
// its findings fall below the entry's minimum, and a split part leaves the run.
func TestLiveGitHubIssueSplitAndMinimum(t *testing.T) {
	g := newLiveGitHub(t)
	p := g.publisher(saga.PublisherConfig{Split: saga.SplitControl, MinPriority: "P1"})

	both := func(sastPriority string) report.Data {
		d := g.onMain(map[string][]sarif.Result{
			"sca":  {upgradeFinding("api", "CVE-2026-0001", "P1")},
			"sast": {codeFinding("web", "python.lang.eval", sastPriority, "app/app.py")},
		})
		d.Gate = report.GateSettings{FailOnPriority: "P2"}
		return d
	}
	g.mustPublish(p, both("P1"))
	var sast, sca int64
	for _, i := range g.openCount(2) {
		switch {
		case strings.Contains(i.Body, "control=sast"):
			sast = i.Number
		case strings.Contains(i.Body, "control=sca"):
			sca = i.Number
		}
	}

	// sast still fails the P2 gate, with nothing at P1.
	g.mustPublish(p, both("P2"))
	below := g.jobText("No finding at or above P1 fails the gate")
	if i := g.issue(sast); i.State != "closed" || i.StateReason != "completed" {
		t.Errorf("sast #%d = %s/%s, want closed/completed", sast, i.State, i.StateReason)
	}
	if cs := g.comments(sast); len(cs) != 1 || cs[0] != below {
		t.Errorf("sast comments = %q, want %q", cs, below)
	}

	// sast fails at P1 again and opens a new issue, then leaves the run.
	g.openCount(1)
	g.mustPublish(p, both("P1"))
	sast = 0
	for _, i := range g.openCount(2) {
		if strings.Contains(i.Body, "control=sast") {
			sast = i.Number
		}
	}
	if sast == 0 {
		t.Fatal("sast failing at P1 again opened no issue")
	}
	d := g.onMain(map[string][]sarif.Result{"sca": {upgradeFinding("api", "CVE-2026-0001", "P1")}})
	g.mustPublish(p, d)
	if i := g.issue(sast); i.State != "closed" || i.StateReason != "not_planned" {
		t.Errorf("sast #%d = %s/%s, want closed/not_planned", sast, i.State, i.StateReason)
	}
	if cs := g.comments(sast); len(cs) != 1 || cs[0] != "The run no longer includes control `sast`." {
		t.Errorf("sast comments = %q", cs)
	}
	if i := g.issue(sca); i.State != "open" {
		t.Errorf("sca #%d closed while it still fails", sca)
	}
}

// TestLiveGitHubARefusedAssigneeIsNamed asks for an assignee who cannot be assigned. With push
// access GitHub refuses the issue outright, and the run names the assignee rather than quoting the
// response. (Without push access it creates the issue and drops the assignee silently, which
// TestMetadataGitHubDroppedIsReported covers against the fake.)
func TestLiveGitHubARefusedAssigneeIsNamed(t *testing.T) {
	g := newLiveGitHub(t)
	p := g.publisher(saga.PublisherConfig{Item: &saga.IssueItem{Assignees: []string{"octocat"}}})
	err := g.publish(p, g.onMain(map[string][]sarif.Result{"sca": {upgradeFinding("api", "CVE-2026-0001", "P1")}}))
	want := "create an issue in " + g.repo + ": 422, assignees octocat cannot be assigned to this issue"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
	if n := len(g.open()); n != 0 {
		t.Errorf("open issues = %d, want none", n)
	}
}
