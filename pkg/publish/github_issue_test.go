package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

// fakeIssue is one issue as the fake GitHub holds it.
type fakeIssue struct {
	Number      int64
	Title, Body string
	State       string
	StateReason string
	Labels      []string
	Assignees   []string
	Milestone   int64
	Type        string
	PullRequest bool
	Comments    []string
}

// fakeGitHub answers the issues, labels and milestones endpoints of one repository, acme/app, from
// memory, and records every request it was sent.
type fakeGitHub struct {
	t          *testing.T
	mu         sync.Mutex
	issues     map[int64]*fakeIssue
	next       int64
	labels     map[string]bool
	labelDefs  map[string]map[string]string // what each label was created with
	milestones []string                     // titles; a milestone's number is its index plus one
	pageSize   int
	requests   []string

	// dropAssignees makes a create answer without its assignees, as GitHub does for a token with no
	// push access.
	dropAssignees bool
	// racedLabel makes the first create of a label answer 422, as if another run had created it.
	racedLabel bool
	// refuse answers every request whose "METHOD path" starts with the key with the status.
	refuse map[string]ghRefusal
}

type ghRefusal struct {
	status      int
	permissions string
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, *httptest.Server) {
	t.Helper()
	f := &fakeGitHub{t: t, issues: map[int64]*fakeIssue{}, next: 1, labels: map[string]bool{}, pageSize: 100,
		labelDefs: map[string]map[string]string{}, refuse: map[string]ghRefusal{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeGitHub) add(i fakeIssue) *fakeIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	i.Number = f.next
	f.next++
	if i.State == "" {
		i.State = "open"
	}
	f.issues[i.Number] = &i
	return &i
}

// writes is every request that changed something.
func (f *fakeGitHub) writes() []string {
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

func (f *fakeGitHub) issue(n int64) *fakeIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issues[n]
}

func (f *fakeGitHub) openIssues() []*fakeIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*fakeIssue
	for n := int64(1); n < f.next; n++ {
		if i := f.issues[n]; i != nil && i.State == "open" && !i.PullRequest {
			out = append(out, i)
		}
	}
	return out
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := r.Method + " " + r.URL.Path
	f.requests = append(f.requests, line)
	for prefix, ref := range f.refuse {
		if strings.HasPrefix(line, prefix) {
			if ref.permissions != "" {
				w.Header().Set("X-Accepted-GitHub-Permissions", ref.permissions)
			}
			w.WriteHeader(ref.status)
			_, _ = w.Write([]byte(`{"message":"refused"}`))
			return
		}
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/repos/acme/app/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	var in map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&in)
	}
	parts := strings.Split(rest, "/")
	switch {
	case rest == "issues" && r.Method == http.MethodGet:
		label := r.URL.Query().Get("label" + "s")
		var all []*fakeIssue
		for n := int64(1); n < f.next; n++ {
			if i := f.issues[n]; i != nil && i.State == "open" && slices.Contains(i.Labels, label) {
				all = append(all, i)
			}
		}
		f.page(w, r, len(all), func(k int) any { return f.wire(all[k]) })
	case rest == "issues" && r.Method == http.MethodPost:
		i := &fakeIssue{Number: f.next, State: "open", Title: str(in["title"]), Body: str(in["body"]), Type: str(in["type"])}
		f.next++
		for _, l := range strs(in["labels"]) {
			if f.labels[l] {
				i.Labels = append(i.Labels, l)
			}
		}
		if !f.dropAssignees {
			i.Assignees = strs(in["assignees"])
		}
		if m, ok := in["milestone"].(float64); ok {
			i.Milestone = int64(m)
		}
		f.issues[i.Number] = i
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
		case len(parts) == 2 && r.Method == http.MethodPatch:
			if b, ok := in["body"]; ok {
				i.Body = str(b)
			}
			if s, ok := in["state"]; ok {
				i.State, i.StateReason = str(s), str(in["state_reason"])
			}
		case len(parts) == 3 && parts[2] == "comments" && r.Method == http.MethodPost:
			i.Comments = append(i.Comments, str(in["body"]))
		case len(parts) == 3 && parts[2] == "labels" && r.Method == http.MethodPost:
			i.Labels = append(i.Labels, strs(in["labels"])...)
		case len(parts) == 4 && parts[2] == "labels" && r.Method == http.MethodDelete:
			k := slices.Index(i.Labels, parts[3])
			if k < 0 {
				http.NotFound(w, r)
				return
			}
			i.Labels = slices.Delete(i.Labels, k, k+1)
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(f.wire(i))
	case len(parts) == 2 && parts[0] == "labels" && r.Method == http.MethodGet:
		if !f.labels[parts[1]] {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"name": parts[1]})
	case rest == "labels" && r.Method == http.MethodPost:
		name := str(in["name"])
		f.labels[name] = true
		f.labelDefs[name] = map[string]string{"color": str(in["color"]), "description": str(in["description"])}
		if f.racedLabel {
			f.racedLabel = false
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case rest == "milestones" && r.Method == http.MethodGet:
		f.page(w, r, len(f.milestones), func(k int) any {
			return map[string]any{"number": k + 1, "title": f.milestones[k]}
		})
	default:
		http.NotFound(w, r)
	}
}

// page writes one page of a list, with the Link header GitHub sends when there is another.
func (f *fakeGitHub) page(w http.ResponseWriter, r *http.Request, total int, item func(int) any) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	page = max(page, 1)
	start := min((page-1)*f.pageSize, total)
	end := min(start+f.pageSize, total)
	if end < total {
		q := r.URL.Query()
		q.Set("page", strconv.Itoa(page+1))
		w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?%s>; rel="next"`, r.Host, r.URL.Path, q.Encode()))
	}
	out := []any{}
	for k := start; k < end; k++ {
		out = append(out, item(k))
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeGitHub) wire(i *fakeIssue) map[string]any {
	labels := []map[string]string{}
	for _, l := range i.Labels {
		labels = append(labels, map[string]string{"name": l})
	}
	assignees := []map[string]string{}
	for _, a := range i.Assignees {
		assignees = append(assignees, map[string]string{"login": a})
	}
	out := map[string]any{"number": i.Number, "body": i.Body, "labels": labels, "assignees": assignees}
	if i.Milestone != 0 {
		out["milestone"] = map[string]any{"number": i.Milestone}
	}
	if i.Type != "" {
		out["type"] = map[string]any{"name": i.Type}
	}
	if i.PullRequest {
		out["pull_request"] = map[string]any{"url": "x"}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strs(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			out = append(out, str(x))
		}
	}
	return out
}

// issueEnv is a GitHub Actions job against the fake.
func issueEnv(t *testing.T, apiURL string) {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_API_URL", apiURL)
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_TOKEN", "secret")
}

// issuePublisher builds the publisher against the fake, with an unpaced client so a test does not
// wait out the spacing between writes.
func issuePublisher(t *testing.T, srv *httptest.Server, cfg saga.PublisherConfig) githubIssuePublisher {
	t.Helper()
	issueEnv(t, srv.URL)
	cfg.Kind = "github-issue"
	p, err := For(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gp, ok := p.(githubIssuePublisher)
	if !ok {
		t.Fatalf("publisher is %T", p)
	}
	gp.client = srv.Client()
	return gp
}

// onMain is a run of the demo project on its default branch, in job 77.
func onMain(controls map[string][]sarif.Result) report.Data {
	d := runOver(controls)
	d.CI = &ci.Context{Branch: "main", DefaultBranch: "main", RunID: "77",
		URL: "https://github.com/acme/app/actions/runs/77"}
	return d
}

func publishRun(t *testing.T, p githubIssuePublisher, data report.Data) {
	t.Helper()
	if err := p.PublishRun(context.Background(), data, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAFailingRunOpensOneIssueAndAPassingRunClosesIt(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{})

	failing := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	publishRun(t, p, failing)
	open := gh.openIssues()
	if len(open) != 1 {
		t.Fatalf("open issues = %d, want 1", len(open))
	}
	i := open[0]
	if !slices.Contains(i.Labels, "draugr") || i.Title == "" || !strings.Contains(i.Body, "<!-- draugr:issue v1 project=demo") {
		t.Errorf("issue = %+v", i)
	}

	publishRun(t, p, onMain(map[string][]sarif.Result{"sca": nil}))
	i = gh.issue(i.Number)
	if i.State != "closed" || i.StateReason != "completed" {
		t.Errorf("state = %s/%s, want closed/completed", i.State, i.StateReason)
	}
	want := "The gate passes on `main` in [job 77](https://github.com/acme/app/actions/runs/77)."
	if len(i.Comments) != 1 || i.Comments[0] != want {
		t.Errorf("comments = %q, want %q", i.Comments, want)
	}
}

func TestAnUnchangedRunSendsNoWrite(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{})
	failing := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	publishRun(t, p, failing)
	before := len(gh.writes())

	// A later job with the same findings.
	failing.CI = &ci.Context{Branch: "main", DefaultBranch: "main", RunID: "78",
		URL: "https://github.com/acme/app/actions/runs/78"}
	publishRun(t, p, failing)
	if got := gh.writes()[before:]; len(got) != 0 {
		t.Errorf("an unchanged run wrote %q", got)
	}

	failing.Run.Controls["sca"].Report.Results[0].Location.StartLine = 9
	publishRun(t, p, failing)
	got := gh.writes()[before:]
	if len(got) != 1 || got[0] != "PATCH /repos/acme/app/issues/1" {
		t.Errorf("a changed run wrote %q, want one PATCH", got)
	}
}

func TestTwoProjectsAndTwoScopesKeepTheirOwnIssues(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{})
	findings := map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}}

	demo := onMain(findings)
	other := onMain(findings)
	other.Project = "shop"
	scoped := onMain(findings)
	scoped.Requested.Controls = []string{"sca"}
	for _, d := range []report.Data{demo, other, scoped} {
		publishRun(t, p, d)
	}
	if n := len(gh.openIssues()); n != 3 {
		t.Fatalf("open issues = %d, want one per project and scope", n)
	}

	// The shop project passing closes the shop issue and nothing else.
	passing := onMain(map[string][]sarif.Result{"sca": nil})
	passing.Project = "shop"
	publishRun(t, p, passing)
	if gh.issue(2).State != "closed" || gh.issue(1).State != "open" || gh.issue(3).State != "open" {
		t.Errorf("states = %s %s %s", gh.issue(1).State, gh.issue(2).State, gh.issue(3).State)
	}
}

func TestAnIssueOnTheSecondPageIsFound(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	gh.pageSize = 2
	gh.labels["draugr"] = true
	for range 3 {
		gh.add(fakeIssue{Title: "someone else's", Body: "unrelated", Labels: []string{"draugr"}})
	}
	gh.add(fakeIssue{Title: "a pull request", Body: "x", Labels: []string{"draugr"}, PullRequest: true})
	p := issuePublisher(t, srv, saga.PublisherConfig{})
	failing := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	publishRun(t, p, failing)
	mine := gh.openIssues()[3]

	// Rewritten on the next change rather than opened again.
	failing.Run.Controls["sca"].Report.Results[0].Location.StartLine = 9
	publishRun(t, p, failing)
	if n := len(gh.openIssues()); n != 4 {
		t.Errorf("open issues = %d, want the third page's issue rewritten, not another", n)
	}
	if !strings.Contains(gh.issue(mine.Number).Body, "go.mod:9") {
		t.Errorf("issue #%d not rewritten:\n%s", mine.Number, gh.issue(mine.Number).Body)
	}
}

func TestADuplicateIsClosedAgainstTheOldest(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{})
	failing := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	publishRun(t, p, failing)
	first := gh.issue(1)
	gh.add(fakeIssue{Title: first.Title, Body: first.Body, Labels: []string{"draugr"}})

	publishRun(t, p, failing)
	dup := gh.issue(2)
	if dup.State != "closed" || dup.StateReason != "duplicate" || len(dup.Comments) != 1 || dup.Comments[0] != "Duplicate of #1." {
		t.Errorf("duplicate = %+v", dup)
	}
	if gh.issue(1).State != "open" {
		t.Error("the oldest issue was closed")
	}
}

func TestBelowTheMinimumTheIssueClosesSayingSo(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{MinPriority: "P1"})
	data := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	data.Gate = report.GateSettings{FailOnPriority: "P2"}
	publishRun(t, p, data)

	data.Run.Controls["sca"].Report.Results[0].Priority = "P2"
	publishRun(t, p, data)
	i := gh.issue(1)
	want := "No finding at or above P1 fails the gate on `main` in [job 77](https://github.com/acme/app/actions/runs/77)."
	if i.State != "closed" || len(i.Comments) != 1 || i.Comments[0] != want {
		t.Errorf("issue = %s, comments %q", i.State, i.Comments)
	}
}

func TestASplitIssueWhosePartLeftTheRunIsClosed(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{Split: saga.SplitControl})
	publishRun(t, p, onMain(map[string][]sarif.Result{
		"sca":  {codeFinding("api", "c1", "P1", "go.mod")},
		"sast": {codeFinding("web", "r1", "P1", "a.go")},
	}))
	if n := len(gh.openIssues()); n != 2 {
		t.Fatalf("open issues = %d, want one per control", n)
	}

	publishRun(t, p, onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}}))
	var sast *fakeIssue
	for _, n := range []int64{1, 2} {
		if strings.Contains(gh.issue(n).Body, "control=sast") {
			sast = gh.issue(n)
		}
	}
	if sast == nil || sast.State != "closed" || sast.StateReason != "not_planned" ||
		len(sast.Comments) != 1 || sast.Comments[0] != "The run no longer includes control `sast`." {
		t.Errorf("sast issue = %+v", sast)
	}
	if n := len(gh.openIssues()); n != 1 {
		t.Errorf("open issues = %d, want the sca one", n)
	}
}

func TestOnlyATrackedBranchChangesAnIssue(t *testing.T) {
	for _, c := range []struct {
		name     string
		ci       *ci.Context
		branches []string
		want     string
	}{
		{"not CI", nil, nil, "not a CI run"},
		{"pull request", &ci.Context{Branch: "main", DefaultBranch: "main", PullRequest: true}, nil, "a pull-request run"},
		{"tag build", &ci.Context{DefaultBranch: "main"}, nil, "not a branch build"},
		{"other branch", &ci.Context{Branch: "dev", DefaultBranch: "main"}, nil, "branch dev is not the default branch, main"},
		{"unknown default", &ci.Context{Branch: "main"}, nil, "the default branch is unknown"},
		{"outside branches", &ci.Context{Branch: "main", DefaultBranch: "main"}, []string{"release/*"}, "branch main is not in branches"},
		{"glob", &ci.Context{Branch: "release/2.1", DefaultBranch: "main"}, []string{"main", "release/*"}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			ok, why := trackedBranch(c.ci, c.branches)
			if ok != (c.want == "") || !strings.Contains(why, c.want) {
				t.Errorf("trackedBranch = %v, %q; want %q", ok, why, c.want)
			}
		})
	}
}

func TestASkippedRunSaysWhyAndSendsNothing(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := issuePublisher(t, srv, saga.PublisherConfig{})
	data := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	data.CI.PullRequest = true
	publishRun(t, p, data)
	data.CI.PullRequest = false
	data.Gate.Disabled = true
	publishRun(t, p, data)

	if len(gh.requests) != 0 {
		t.Errorf("a skipped run sent %q", gh.requests)
	}
	for _, want := range []string{`reason="a pull-request run"`, `reason="the gate is disabled"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %s:\n%s", want, logs.String())
		}
	}
}

func TestARunWithNoProjectIsRefused(t *testing.T) {
	_, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{})
	data := onMain(nil)
	data.Project = ""
	err := p.PublishRun(context.Background(), data, nil)
	if err == nil || !strings.Contains(err.Error(), "names no project") {
		t.Errorf("err = %v", err)
	}
}

func TestACreatedIssueCarriesTheItemMetadata(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	gh.milestones = []string{"Q3", "Hardening"}
	gh.pageSize = 1
	p := issuePublisher(t, srv, saga.PublisherConfig{Label: "security", Item: &saga.IssueItem{
		Labels: []string{"triage"}, Assignees: []string{"octocat"}, Milestone: "Hardening", Type: "Bug",
	}})
	publishRun(t, p, onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}}))
	i := gh.issue(1)
	if !slices.Equal(i.Labels, []string{"security", "triage", "draugr:priority:P1"}) || !slices.Equal(i.Assignees, []string{"octocat"}) ||
		i.Milestone != 2 || i.Type != "Bug" {
		t.Errorf("issue = %+v", i)
	}
	if !gh.labels["security"] || !gh.labels["triage"] {
		t.Errorf("labels not created: %v", gh.labels)
	}
}

func TestAMissingMilestoneIsNamed(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	gh.milestones = []string{"Q3"}
	p := issuePublisher(t, srv, saga.PublisherConfig{Item: &saga.IssueItem{Milestone: "Hardening"}})
	err := p.PublishRun(context.Background(),
		onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}}), nil)
	if err == nil || !strings.Contains(err.Error(), `item.milestone "Hardening" is not a milestone of acme/app, open or closed`) {
		t.Errorf("err = %v", err)
	}
}

func TestMetadataGitHubDroppedIsReported(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	gh.dropAssignees = true
	p := issuePublisher(t, srv, saga.PublisherConfig{Item: &saga.IssueItem{Assignees: []string{"octocat"}}})
	err := p.PublishRun(context.Background(),
		onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}}), nil)
	if err == nil || !strings.Contains(err.Error(), "created #1 in acme/app without assignee octocat") {
		t.Errorf("err = %v", err)
	}
}

func TestALabelAnotherRunCreatedIsReadAgain(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	gh.racedLabel = true
	p := issuePublisher(t, srv, saga.PublisherConfig{})
	publishRun(t, p, onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}}))
	want := []string{"GET /repos/acme/app/labels/draugr", "POST /repos/acme/app/labels", "GET /repos/acme/app/labels/draugr"}
	if got := gh.requests[1:4]; !slices.Equal(got, want) {
		t.Errorf("requests = %q, want %q", got, want)
	}
	if len(gh.openIssues()) != 1 {
		t.Error("no issue opened after the label race")
	}
}

func TestARemovedItemLabelIsAddedBack(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{Item: &saga.IssueItem{Labels: []string{"triage"}}})
	failing := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	publishRun(t, p, failing)
	gh.issue(1).Labels = []string{"draugr"}

	publishRun(t, p, failing)
	if !slices.Contains(gh.issue(1).Labels, "triage") {
		t.Errorf("labels = %v", gh.issue(1).Labels)
	}
	before := len(gh.writes())
	publishRun(t, p, failing)
	if got := gh.writes()[before:]; len(got) != 0 {
		t.Errorf("a label already there was added again: %q", got)
	}
}

func TestGitHubRefusalsSayWhatToFix(t *testing.T) {
	for _, c := range []struct {
		name string
		ref  ghRefusal
		want string
	}{
		{"permission", ghRefusal{status: http.StatusForbidden, permissions: "issues=write"},
			"list issues in acme/app: 403, the token needs issues=write. For GITHUB_TOKEN, grant it in the workflow with `permissions: issues: write`"},
		{"forbidden", ghRefusal{status: http.StatusForbidden}, `list issues in acme/app: 403: {"message":"refused"}`},
		{"issues off", ghRefusal{status: http.StatusGone}, "410, issues are turned off for the repository"},
		{"not found", ghRefusal{status: http.StatusNotFound}, "404, the repository or item does not exist, or the token cannot see it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			gh, srv := newFakeGitHub(t)
			gh.refuse["GET /repos/acme/app/issues"] = c.ref
			p := issuePublisher(t, srv, saga.PublisherConfig{})
			err := p.PublishRun(context.Background(), onMain(nil), nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestAFieldGitHubRefusesIsNamed(t *testing.T) {
	refused := &githubStatusError{status: http.StatusUnprocessableEntity, what: "create an issue", repo: "acme/app",
		body: `{"message":"Validation Failed","errors":[{"message":"assignees octocat cannot be assigned to this issue","field":"assignees"}]}`}
	want := "github-issue publisher: create an issue in acme/app: 422, assignees octocat cannot be assigned to this issue"
	if got := refused.Error(); got != want {
		t.Errorf("err = %q, want %q", got, want)
	}
	bare := &githubStatusError{status: http.StatusUnprocessableEntity, what: "create an issue", repo: "acme/app",
		body: `{"message":"Validation Failed"}`}
	if got := bare.Error(); !strings.HasSuffix(got, `422: {"message":"Validation Failed"}`) {
		t.Errorf("err = %q, want GitHub's body when it names no field", got)
	}
}

func TestAFailedWriteIsReportedAndTheRestStillRun(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{Split: saga.SplitControl})
	publishRun(t, p, onMain(map[string][]sarif.Result{
		"sca":  {codeFinding("api", "c1", "P1", "go.mod")},
		"sast": {codeFinding("web", "r1", "P1", "a.go")},
	}))
	gh.refuse["POST /repos/acme/app/issues/1/comments"] = ghRefusal{status: http.StatusInternalServerError}
	err := p.PublishRun(context.Background(), onMain(map[string][]sarif.Result{"sca": nil, "sast": nil}), nil)
	if err == nil || !strings.Contains(err.Error(), "comment on #1") {
		t.Errorf("err = %v", err)
	}
	if gh.issue(2).State != "closed" {
		t.Error("one failed close stopped the other")
	}
}

func TestTheGitHubIssuePublisherNeedsARepositoryAndAToken(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_TOKEN", "")
	p, err := For(saga.PublisherConfig{Kind: "github-issue"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(skipPublisher); !ok {
		t.Errorf("outside Actions = %T, want a skip", p)
	}

	t.Setenv("GITHUB_ACTIONS", "true")
	_, err = For(saga.PublisherConfig{Kind: "github-issue"})
	if err == nil || !strings.Contains(err.Error(), "repo (or $GITHUB_REPOSITORY)") ||
		!strings.Contains(err.Error(), "$GITHUB_TOKEN, mapped into the job's env") {
		t.Errorf("err = %v", err)
	}

	p, err = For(saga.PublisherConfig{Kind: "github-issue"})
	if p != nil && err == nil {
		t.Error("built without a token")
	}
	if err := (githubIssuePublisher{}).Publish(context.Background(), nil); err == nil {
		t.Error("Publish without the run did nothing")
	}
}

func TestUntrackedNamesComponentsNoSelectionCovers(t *testing.T) {
	model := &saga.Model{
		Components: []saga.Component{
			{Name: "api", Labels: map[string]string{"team": "payments"}},
			{Name: "web", Labels: map[string]string{"team": "web"}},
			{Name: "batch"},
		},
	}
	if got := Untracked(model); got != nil {
		t.Errorf("no issue entry: %v", got)
	}
	model.Config.Publishers = []saga.PublisherConfig{
		{Kind: "github-pr-comment"},
		{Kind: "github-issue", Select: &saga.PublisherSelect{Labels: map[string]string{"team": "payments"}}},
		{Kind: "github-issue", Select: &saga.PublisherSelect{Components: []string{"web"}}},
	}
	if got := Untracked(model); !slices.Equal(got, []string{"batch"}) {
		t.Errorf("untracked = %v", got)
	}
	model.Config.Publishers = append(model.Config.Publishers,
		saga.PublisherConfig{Kind: "github-issue", Select: &saga.PublisherSelect{Controls: []string{"sca"}}})
	if got := Untracked(model); got != nil {
		t.Errorf("a controls-only select covers every component: %v", got)
	}
}

func TestTheJobIsNamedWithWhatTheRunRecorded(t *testing.T) {
	f := markdownFormat{}
	for _, c := range []struct {
		ctx  ci.Context
		want string
	}{
		{ci.Context{RunID: "77", URL: "https://ci.example/77"}, "[job 77](https://ci.example/77)"},
		{ci.Context{URL: "https://ci.example/77"}, "[the job](https://ci.example/77)"},
		{ci.Context{RunID: "77"}, "job 77"},
		{ci.Context{}, ""},
	} {
		if got := jobRef(f, &c.ctx); got != c.want {
			t.Errorf("jobRef(%+v) = %q, want %q", c.ctx, got, c.want)
		}
	}
}

func TestAMarkerValueReadsBackAsWritten(t *testing.T) {
	for _, s := range []string{"demo", "my app", "a--b", "team=web,ops", "100%", "%"} {
		if got := unescapeMarker(markerValue(s)); got != s {
			t.Errorf("unescapeMarker(markerValue(%q)) = %q", s, got)
		}
	}
}

// classified is a finding on a component declared with an exposure and a criticality.
func classified(component, control, priority, exposure, criticality string) sarif.Result {
	r := codeFinding(component, control+"-rule", priority, "main.go")
	r.Exposure, r.Criticality = exposure, criticality
	return r
}

func TestFactLabelsFollowTheFindings(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{LabelBy: saga.LabelFacts})
	data := onMain(map[string][]sarif.Result{
		"sca":  {classified("web", "sca", "P1", "public", "critical")},
		"sast": {classified("api", "sast", "P2", "internal", "important")},
	})
	data.Gate = report.GateSettings{FailOnPriority: "P2"}
	publishRun(t, p, data)
	want := []string{"draugr", "draugr:control:sast", "draugr:control:sca", "draugr:criticality:critical",
		"draugr:criticality:important", "draugr:exposure:internal", "draugr:exposure:public", "draugr:priority:P1"}
	if got := gh.issue(1).Labels; !slices.Equal(got, want) {
		t.Errorf("labels = %q, want %q", got, want)
	}

	// The P1 is fixed and the sast scan fails: the labels follow, removing what no longer applies.
	delete(data.Run.Controls, "sca")
	data.Incomplete = true
	data.Run.ScanErrors = map[string][]string{"sast": {"semgrep: exit 2"}}
	publishRun(t, p, data)
	got := slices.Clone(gh.issue(1).Labels)
	slices.Sort(got)
	want = []string{"draugr", "draugr:control:sast", "draugr:criticality:important", "draugr:exposure:internal",
		"draugr:incomplete", "draugr:priority:P2"}
	if !slices.Equal(got, want) {
		t.Errorf("labels = %q, want %q", got, want)
	}

	before := len(gh.writes())
	publishRun(t, p, data)
	if w := gh.writes()[before:]; len(w) != 0 {
		t.Errorf("unchanged labels were written again: %q", w)
	}
}

func TestFactLabelsSayWhatTheyCarry(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{LabelBy: saga.LabelFacts})
	publishRun(t, p, onMain(map[string][]sarif.Result{"sca": {classified("web", "sca", "P1", "public", "critical")}}))
	if d := gh.labelDefs["draugr:priority:P1"]; d["color"] != "b60205" || !strings.Contains(d["description"], "highest priority") {
		t.Errorf("priority label = %v", d)
	}
	if d := gh.labelDefs["draugr"]; d["description"] != "" {
		t.Errorf("the tracking label was described: %v", d)
	}
	for _, c := range []struct{ name, color, says string }{
		{"draugr:priority:P2", "d93f0b", "highest priority"},
		{"draugr:priority:P3", "fbca04", "highest priority"},
		{"draugr:priority:P4", "c5def5", "highest priority"},
		{"draugr:control:sca", "1d76db", "control"},
		{"draugr:exposure:public", "5319e7", "exposure"},
		{"draugr:criticality:critical", "5319e7", "criticality"},
		{"draugr:incomplete", "e99695", "scan error"},
	} {
		color, description := labelStyle(c.name)
		if color != c.color || !strings.Contains(description, c.says) || len(description) > 100 {
			t.Errorf("%s: %s %q", c.name, color, description)
		}
	}
}

func TestEachSplitPartKeepsItsOwnFactLabels(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{Split: saga.SplitControl, LabelBy: saga.LabelBy{"priority", "control"}})
	data := onMain(map[string][]sarif.Result{
		"sca":  {classified("web", "sca", "P1", "public", "critical")},
		"sast": {classified("api", "sast", "P2", "internal", "important")},
	})
	data.Gate = report.GateSettings{FailOnPriority: "P2"}
	publishRun(t, p, data)
	byControl := map[string][]string{}
	for _, i := range gh.openIssues() {
		byControl[strings.SplitN(i.Title, " ", 2)[0]] = i.Labels
	}
	if got := byControl["sast"]; !slices.Equal(got, []string{"draugr", "draugr:control:sast", "draugr:priority:P2"}) {
		t.Errorf("sast labels = %q", got)
	}
	if got := byControl["sca"]; !slices.Equal(got, []string{"draugr", "draugr:control:sca", "draugr:priority:P1"}) {
		t.Errorf("sca labels = %q", got)
	}
}

func TestAnEmptyLabelByKeepsNoFactLabels(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	failing := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	publishRun(t, issuePublisher(t, srv, saga.PublisherConfig{}), failing)
	if got := gh.issue(1).Labels; !slices.Equal(got, []string{"draugr", "draugr:priority:P1"}) {
		t.Fatalf("unset labelBy: labels = %q", got)
	}
	publishRun(t, issuePublisher(t, srv, saga.PublisherConfig{LabelBy: saga.LabelBy{}}), failing)
	if got := gh.issue(1).Labels; !slices.Equal(got, []string{"draugr"}) {
		t.Errorf("empty labelBy: labels = %q", got)
	}
}

func TestAFactLabelChangedByHandIsPutRight(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{})
	failing := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	publishRun(t, p, failing)
	gh.issue(1).Labels = []string{"draugr", "Draugr:Priority:P3", "wontfix"}
	publishRun(t, p, failing)
	if got := gh.issue(1).Labels; !slices.Equal(got, []string{"draugr", "wontfix", "draugr:priority:P1"}) {
		t.Errorf("labels = %q", got)
	}
}

func TestAFactLabelAlreadyGoneIsNotAFailure(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{})
	failing := onMain(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
	publishRun(t, p, failing)
	failing.Run.Controls["sca"].Report.Results[0].Priority = "P2"
	failing.Gate = report.GateSettings{FailOnPriority: "P2"}
	gh.refuse["DELETE /repos/acme/app/issues/1/labels/"] = ghRefusal{status: http.StatusNotFound}
	publishRun(t, p, failing)

	gh.refuse = map[string]ghRefusal{"DELETE /repos/acme/app/issues/1/labels/": {status: http.StatusForbidden}}
	failing.Run.Controls["sca"].Report.Results[0].Priority = "P1"
	gh.issue(1).Labels = []string{"draugr", "draugr:priority:P2"}
	if err := p.PublishRun(context.Background(), failing, nil); err == nil || !strings.Contains(err.Error(), "remove label draugr:priority:P2") {
		t.Errorf("err = %v", err)
	}
}
