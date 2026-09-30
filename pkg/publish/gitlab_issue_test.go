package publish

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// glIssue is one issue as the fake GitLab holds it.
type glIssue struct {
	IID          int64
	Title, Body  string
	State        string
	Labels       []string
	Assignees    []string
	Milestone    int64
	Type         string
	Confidential bool
	Notes        []string
}

type glMember struct {
	ID       int64
	Username string
}

// fakeGitLab answers the issues, notes, members and milestones endpoints of one project, acme/app,
// from memory, and records every request it was sent.
type fakeGitLab struct {
	t          *testing.T
	mu         sync.Mutex
	issues     map[int64]*glIssue
	next       int64
	members    []glMember
	milestones []string // titles; a milestone's id is its index plus 100
	pageSize   int
	requests   []string
	bodies     []map[string]any // the body of every write, in order
	tokens     []string         // the PRIVATE-TOKEN of every request

	// dropAssignees makes a create answer without its assignees, as GitLab does for a user with no
	// role to set them.
	dropAssignees bool
	// dropConfidential makes a create answer as a public issue.
	dropConfidential bool
	// refuse answers every request whose "METHOD path" starts with the key with the status.
	refuse map[string]int
}

const glProject = "/api/v4/projects/acme%2Fapp/"

func newFakeGitLab(t *testing.T) (*fakeGitLab, *httptest.Server) {
	t.Helper()
	f := &fakeGitLab{t: t, issues: map[int64]*glIssue{}, next: 1, pageSize: 100, refuse: map[string]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeGitLab) add(i glIssue) *glIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	i.IID = f.next
	f.next++
	if i.State == "" {
		i.State = "opened"
	}
	f.issues[i.IID] = &i
	return &i
}

func (f *fakeGitLab) issue(n int64) *glIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issues[n]
}

func (f *fakeGitLab) openIssues() []*glIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*glIssue
	for n := int64(1); n < f.next; n++ {
		if i := f.issues[n]; i != nil && i.State == "opened" {
			out = append(out, i)
		}
	}
	return out
}

// writes is every request that changed something.
func (f *fakeGitLab) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if !strings.HasPrefix(r, "GET ") {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeGitLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := r.Method + " " + r.URL.EscapedPath()
	f.requests = append(f.requests, line)
	f.tokens = append(f.tokens, r.Header.Get("PRIVATE-TOKEN"))
	for prefix, status := range f.refuse {
		if strings.HasPrefix(line, prefix) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"refused"}`))
			return
		}
	}
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), glProject)
	if !ok {
		http.NotFound(w, r)
		return
	}
	var in map[string]any
	if r.Method != http.MethodGet {
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.bodies = append(f.bodies, in)
	}
	q := r.URL.Query()
	parts := strings.Split(rest, "/")
	switch {
	case rest == "issues" && r.Method == http.MethodGet:
		var all []*glIssue
		for n := int64(1); n < f.next; n++ {
			if i := f.issues[n]; i != nil && i.State == q.Get("state") && slices.Contains(i.Labels, q.Get("labels")) {
				all = append(all, i)
			}
		}
		f.page(w, r, len(all), func(k int) any { return f.wire(all[k]) })
	case rest == "issues" && r.Method == http.MethodPost:
		i := &glIssue{IID: f.next, State: "opened", Title: str(in["title"]), Body: str(in["description"]),
			Type: "issue", Confidential: in["confidential"] == true && !f.dropConfidential}
		f.next++
		if t := str(in["issue_type"]); t != "" {
			i.Type = t
		}
		i.Labels = strings.Split(str(in["labels"]), ",")
		var ids []int64
		if id, ok := in["assignee_id"].(float64); ok {
			ids = append(ids, int64(id))
		}
		if l, ok := in["assignee_ids"].([]any); ok {
			for _, id := range l {
				ids = append(ids, int64(id.(float64)))
			}
		}
		for _, id := range ids {
			for _, m := range f.members {
				if m.ID == id && !f.dropAssignees {
					i.Assignees = append(i.Assignees, m.Username)
				}
			}
		}
		if m, ok := in["milestone_id"].(float64); ok {
			i.Milestone = int64(m)
		}
		f.issues[i.IID] = i
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(f.wire(i))
	case len(parts) >= 2 && parts[0] == "issues":
		n, _ := strconv.ParseInt(parts[1], 10, 64)
		i := f.issues[n]
		if i == nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case len(parts) == 2 && r.Method == http.MethodPut:
			if b, ok := in["description"]; ok {
				i.Body = str(b)
			}
			if str(in["state_event"]) == "close" {
				i.State = "closed"
			}
			if add := str(in["add_labels"]); add != "" {
				i.Labels = append(i.Labels, strings.Split(add, ",")...)
			}
			for _, l := range strings.Split(str(in["remove_labels"]), ",") {
				i.Labels = slices.DeleteFunc(i.Labels, func(have string) bool { return have == l })
			}
		case len(parts) == 3 && parts[2] == "notes" && r.Method == http.MethodPost:
			i.Notes = append(i.Notes, str(in["body"]))
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(f.wire(i))
	case rest == "members/all" && r.Method == http.MethodGet:
		var found []glMember
		for _, m := range f.members {
			if strings.Contains(strings.ToLower(m.Username), strings.ToLower(q.Get("query"))) {
				found = append(found, m)
			}
		}
		f.page(w, r, len(found), func(k int) any {
			return map[string]any{"id": found[k].ID, "username": found[k].Username}
		})
	case rest == "milestones" && r.Method == http.MethodGet:
		if q.Get("include_ancestors") != "true" {
			f.t.Errorf("milestones read without the groups': %s", r.URL.RawQuery)
		}
		out := []any{}
		for k, title := range f.milestones {
			if title == q.Get("title") {
				out = append(out, map[string]any{"id": k + 100, "title": title})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	default:
		http.NotFound(w, r)
	}
}

// page writes one page of a list, with the X-Next-Page header GitLab sends when there is another.
func (f *fakeGitLab) page(w http.ResponseWriter, r *http.Request, total int, item func(int) any) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	page = max(page, 1)
	start := min((page-1)*f.pageSize, total)
	end := min(start+f.pageSize, total)
	if end < total {
		w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
	}
	out := []any{}
	for k := start; k < end; k++ {
		out = append(out, item(k))
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeGitLab) wire(i *glIssue) map[string]any {
	assignees := []map[string]string{}
	for _, a := range i.Assignees {
		assignees = append(assignees, map[string]string{"username": a})
	}
	out := map[string]any{"iid": i.IID, "description": i.Body, "labels": i.Labels, "assignees": assignees,
		"issue_type": i.Type, "confidential": i.Confidential}
	if i.Milestone != 0 {
		out["milestone"] = map[string]any{"id": i.Milestone}
	}
	return out
}

// gitlabEnv is a GitLab CI job against the fake.
func gitlabEnv(t *testing.T, apiURL string) {
	t.Helper()
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_API_V4_URL", apiURL+"/api/v4/")
	t.Setenv("CI_PROJECT_ID", "acme/app")
	t.Setenv("GITLAB_TOKEN", "secret")
}

// gitlabIssues builds the publisher against the fake, with an unpaced client.
func gitlabIssues(t *testing.T, srv *httptest.Server, cfg saga.PublisherConfig) gitlabIssuePublisher {
	t.Helper()
	gitlabEnv(t, srv.URL)
	cfg.Kind = "gitlab-issue"
	p, err := For(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gp, ok := p.(gitlabIssuePublisher)
	if !ok {
		t.Fatalf("publisher is %T", p)
	}
	gp.client = srv.Client()
	return gp
}

func publishGitLab(t *testing.T, p gitlabIssuePublisher, data report.Data) {
	t.Helper()
	if err := p.PublishRun(context.Background(), data, nil); err != nil {
		t.Fatal(err)
	}
}

func failingSCA() report.Data {
	return onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
}

func TestAFailingRunOpensOneGitLabIssueAndAPassingRunClosesIt(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	p := gitlabIssues(t, srv, saga.PublisherConfig{})

	publishGitLab(t, p, failingSCA())
	open := gl.openIssues()
	if len(open) != 1 {
		t.Fatalf("open issues = %d, want 1", len(open))
	}
	i := open[0]
	if !slices.Equal(i.Labels, []string{"draugr", "draugr:priority:P1"}) || i.Title == "" || i.Type != "issue" ||
		!strings.Contains(i.Body, "<!-- draugr:issue v1 project=demo") {
		t.Errorf("issue = %+v", i)
	}
	if !i.Confidential {
		t.Error("an issue listing findings was created public by default")
	}

	publishGitLab(t, p, onMain(map[string][]sarif.Result{"sca": nil}))
	i = gl.issue(i.IID)
	want := "The gate passes on `main` in [job 77](https://github.com/acme/app/actions/runs/77)."
	if i.State != "closed" || len(i.Notes) != 1 || i.Notes[0] != want {
		t.Errorf("issue = %s, notes %q, want closed with %q", i.State, i.Notes, want)
	}
	for _, tok := range gl.tokens {
		if tok != "secret" {
			t.Fatalf("a request went without the token: %q", gl.tokens)
		}
	}
}

func TestAnUnchangedRunWritesNothingToGitLab(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	p := gitlabIssues(t, srv, saga.PublisherConfig{})
	failing := failingSCA()
	publishGitLab(t, p, failing)
	before := len(gl.writes())

	failing.CI = &ci.Context{Branch: "main", DefaultBranch: "main", RunID: "78"}
	publishGitLab(t, p, failing)
	if got := gl.writes()[before:]; len(got) != 0 {
		t.Errorf("an unchanged run wrote %q", got)
	}

	failing.Run.Controls["sca"].Report.Results[0].Location.StartLine = 9
	publishGitLab(t, p, failing)
	got := gl.writes()[before:]
	if len(got) != 1 || got[0] != "PUT "+glProject+"issues/1" || !strings.Contains(gl.issue(1).Body, "go.mod:9") {
		t.Errorf("a changed run wrote %q, want one PUT", got)
	}
}

func TestAGitLabIssueOnTheSecondPageIsFound(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	gl.pageSize = 2
	for range 3 {
		gl.add(glIssue{Title: "someone else's", Body: "unrelated", Labels: []string{"draugr"}})
	}
	gl.add(glIssue{Title: "closed", Body: "x", Labels: []string{"draugr"}, State: "closed"})
	p := gitlabIssues(t, srv, saga.PublisherConfig{})
	failing := failingSCA()
	publishGitLab(t, p, failing)

	failing.Run.Controls["sca"].Report.Results[0].Location.StartLine = 9
	publishGitLab(t, p, failing)
	if n := len(gl.openIssues()); n != 4 {
		t.Errorf("open issues = %d, want the second page's issue rewritten, not another", n)
	}
	if !strings.Contains(gl.issue(5).Body, "go.mod:9") {
		t.Errorf("issue #5 not rewritten:\n%s", gl.issue(5).Body)
	}
}

func TestADuplicateGitLabIssueIsClosedWithANote(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	p := gitlabIssues(t, srv, saga.PublisherConfig{})
	publishGitLab(t, p, failingSCA())
	first := gl.issue(1)
	gl.add(glIssue{Title: first.Title, Body: first.Body, Labels: []string{"draugr"}})

	publishGitLab(t, p, failingSCA())
	if dup := gl.issue(2); dup.State != "closed" || !slices.Equal(dup.Notes, []string{"Duplicate of #1."}) {
		t.Errorf("duplicate = %+v", dup)
	}
	if gl.issue(1).State != "opened" {
		t.Error("the oldest issue was closed")
	}
}

func TestAGitLabIssueIsPublicOnlyWhenTheEntrySaysSo(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	public := false
	p := gitlabIssues(t, srv, saga.PublisherConfig{Item: &saga.IssueItem{Confidential: &public}})
	publishGitLab(t, p, failingSCA())
	if gl.issue(1).Confidential || gl.bodies[0]["confidential"] != false {
		t.Errorf("confidential: false was not sent: %v", gl.bodies[0])
	}
}

func TestACreatedGitLabIssueCarriesTheItemMetadata(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	gl.pageSize = 1
	gl.members = []glMember{{7, "alexandra"}, {8, "alex"}, {9, "sam"}}
	gl.milestones = []string{"Q3", "Hardening"}
	p := gitlabIssues(t, srv, saga.PublisherConfig{Label: "security", Item: &saga.IssueItem{
		Labels: []string{"triage", "Security"}, Assignees: []string{"Alex"}, Milestone: "Hardening", Type: "incident",
	}})
	publishGitLab(t, p, failingSCA())
	i := gl.issue(1)
	if !slices.Equal(i.Labels, []string{"security", "triage", "draugr:priority:P1"}) ||
		!slices.Equal(i.Assignees, []string{"alex"}) || i.Milestone != 101 || i.Type != "incident" {
		t.Errorf("issue = %+v", i)
	}
	if _, many := gl.bodies[0]["assignee_ids"]; many || gl.bodies[0]["assignee_id"] != float64(8) {
		t.Errorf("one assignee was not sent as assignee_id: %v", gl.bodies[0])
	}

	// Two assignees need assignee_ids, which GitLab takes on Premium and above.
	gl2, srv2 := newFakeGitLab(t)
	gl2.members = gl.members
	p = gitlabIssues(t, srv2, saga.PublisherConfig{Item: &saga.IssueItem{Assignees: []string{"alex", "sam"}}})
	publishGitLab(t, p, failingSCA())
	if got := gl2.issue(1).Assignees; !slices.Equal(got, []string{"alex", "sam"}) {
		t.Errorf("assignees = %q, body %v", got, gl2.bodies[0])
	}
}

func TestAnUnknownGitLabMemberOrMilestoneIsNamed(t *testing.T) {
	for _, c := range []struct {
		name string
		item saga.IssueItem
		want string
	}{
		{"member", saga.IssueItem{Assignees: []string{"alex"}}, `item.assignees "alex" is not a member of acme/app`},
		{"milestone", saga.IssueItem{Milestone: "Hardening"},
			`item.milestone "Hardening" is not a milestone of acme/app or its groups, open or closed`},
	} {
		t.Run(c.name, func(t *testing.T) {
			gl, srv := newFakeGitLab(t)
			gl.members = []glMember{{7, "alexandra"}}
			gl.milestones = []string{"Q3"}
			p := gitlabIssues(t, srv, saga.PublisherConfig{Item: &c.item})
			err := p.PublishRun(context.Background(), failingSCA(), nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
			if len(gl.writes()) != 0 {
				t.Errorf("wrote %q before the metadata resolved", gl.writes())
			}
		})
	}
}

func TestMetadataGitLabDroppedIsReported(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	gl.members = []glMember{{8, "alex"}}
	gl.dropAssignees = true
	gl.dropConfidential = true
	p := gitlabIssues(t, srv, saga.PublisherConfig{Item: &saga.IssueItem{Assignees: []string{"alex"}}})
	err := p.PublishRun(context.Background(), failingSCA(), nil)
	if err == nil || !strings.Contains(err.Error(), "created #1 in acme/app without assignee alex, confidential true") {
		t.Errorf("err = %v", err)
	}
}

func TestGitLabLabelsAreSyncedInOneRequest(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	p := gitlabIssues(t, srv, saga.PublisherConfig{Item: &saga.IssueItem{Labels: []string{"triage"}}})
	failing := failingSCA()
	publishGitLab(t, p, failing)

	// Somebody removes triage by hand, and the finding drops to P2.
	gl.issue(1).Labels = []string{"draugr", "draugr:priority:P1"}
	failing.Run.Controls["sca"].Report.Results[0].Priority = "P2"
	failing.Gate = report.GateSettings{FailOnPriority: "P2"}
	before := len(gl.writes())
	publishGitLab(t, p, failing)
	got := gl.writes()[before:]
	// The body names the priority, so it is rewritten too; the labels take one request.
	if len(got) != 2 {
		t.Fatalf("writes = %q, want the body and one label request", got)
	}
	last := gl.bodies[len(gl.bodies)-1]
	if last["add_labels"] != "triage,draugr:priority:P2" || last["remove_labels"] != "draugr:priority:P1" {
		t.Errorf("label request = %v", last)
	}
	if l := gl.issue(1).Labels; !slices.Equal(l, []string{"draugr", "triage", "draugr:priority:P2"}) {
		t.Errorf("labels = %q", l)
	}

	before = len(gl.writes())
	publishGitLab(t, p, failing)
	if w := gl.writes()[before:]; len(w) != 0 {
		t.Errorf("unchanged labels were written again: %q", w)
	}
}

func TestGitLabRefusalsSayWhatToFix(t *testing.T) {
	for _, c := range []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, "list issues in acme/app: 401, the token is not valid or has expired"},
		{http.StatusForbidden, "list issues in acme/app: 403, the token needs Work Item: Create, Read and Update"},
		{http.StatusNotFound, "list issues in acme/app: 404, the project or item does not exist, or the token cannot see it"},
		{http.StatusInternalServerError, `list issues in acme/app: 500: {"message":"refused"}`},
	} {
		t.Run(strconv.Itoa(c.status), func(t *testing.T) {
			gl, srv := newFakeGitLab(t)
			gl.refuse["GET "+glProject+"issues"] = c.status
			p := gitlabIssues(t, srv, saga.PublisherConfig{})
			err := p.PublishRun(context.Background(), failingSCA(), nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestAFailedGitLabWriteIsReportedAndTheRestStillRun(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	p := gitlabIssues(t, srv, saga.PublisherConfig{Split: saga.SplitControl})
	publishGitLab(t, p, onMain(map[string][]sarif.Result{
		"sca":  {codeFinding("api", "c1", "P1", "go.mod")},
		"sast": {codeFinding("web", "r1", "P1", "a.go")},
	}))
	gl.refuse["POST "+glProject+"issues/1/notes"] = http.StatusInternalServerError
	err := p.PublishRun(context.Background(), onMain(map[string][]sarif.Result{"sca": nil, "sast": nil}), nil)
	if err == nil || !strings.Contains(err.Error(), "comment on #1") {
		t.Errorf("err = %v", err)
	}
	if gl.issue(2).State != "closed" {
		t.Error("one failed close stopped the other")
	}
}

func TestAnUnreadableGitLabAnswerIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>"))
	}))
	t.Cleanup(srv.Close)
	p := gitlabIssues(t, srv, saga.PublisherConfig{})
	if err := p.PublishRun(context.Background(), failingSCA(), nil); err == nil || !strings.Contains(err.Error(), "list issues in acme/app") {
		t.Errorf("err = %v", err)
	}
	srv.Close()
	if err := p.PublishRun(context.Background(), failingSCA(), nil); err == nil || !strings.Contains(err.Error(), "list issues in acme/app") {
		t.Errorf("unreachable: err = %v", err)
	}
}

func TestTheGitLabIssuePublisherNeedsAProjectAndAToken(t *testing.T) {
	t.Setenv("GITLAB_CI", "")
	t.Setenv("CI_PROJECT_ID", "")
	t.Setenv("GITLAB_TOKEN", "")
	p, err := For(saga.PublisherConfig{Kind: "gitlab-issue"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(skipPublisher); !ok {
		t.Errorf("outside GitLab CI = %T, want a skip", p)
	}

	t.Setenv("GITLAB_CI", "true")
	_, err = For(saga.PublisherConfig{Kind: "gitlab-issue"})
	if err == nil || !strings.Contains(err.Error(), "repo (or $CI_PROJECT_ID)") ||
		!strings.Contains(err.Error(), "CI_JOB_TOKEN cannot write issues") {
		t.Errorf("err = %v", err)
	}

	t.Setenv("DEPLOY_TOKEN", "secret")
	p, err = For(saga.PublisherConfig{Kind: "gitlab-issue", Repo: "acme/app", TokenEnv: "DEPLOY_TOKEN"})
	if err != nil || p.Kind() != "gitlab-issue" {
		t.Errorf("repo and tokenEnv: %v, %v", p, err)
	}
	if err := (gitlabIssuePublisher{}).Publish(context.Background(), nil); err == nil {
		t.Error("Publish without the run did nothing")
	}
}
