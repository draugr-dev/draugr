package publish

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// twoRules is a run whose sca control fails with a rule action at each of P1 and P2.
func twoRules() map[string][]sarif.Result {
	return map[string][]sarif.Result{"sca": {
		codeFinding("api", "r1", "P1", "a.go"),
		codeFinding("api", "r2", "P2", "b.go"),
	}}
}

func TestGitHubLinksEachChildAsASubIssue(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{Children: saga.ChildrenActions,
		Item: &saga.IssueItem{Type: "Bug"}})
	publishRun(t, p, onMain(twoRules()))

	parent := gh.issue(1)
	if !slices.Equal(parent.SubIssues, []int64{2, 3}) {
		t.Fatalf("sub-issues = %v, want [2 3]", parent.SubIssues)
	}
	if parent.Type != "Bug" || gh.issue(2).Type != "" {
		t.Errorf("types: parent %q, child %q; only the parent takes item.type", parent.Type, gh.issue(2).Type)
	}
	if got := gh.issue(2).Title; got != "P1 · Fix r1" {
		t.Errorf("child title = %q", got)
	}

	// r2 rises to P1, so its child is retitled.
	publishRun(t, p, onMain(map[string][]sarif.Result{"sca": {
		codeFinding("api", "r1", "P1", "a.go"),
		codeFinding("api", "r2", "P1", "b.go"),
	}}))
	if got := gh.issue(3).Title; got != "P1 · Fix r2" {
		t.Errorf("retitled child = %q", got)
	}
}

func TestAGitHubWithoutSubIssuesSaysWhichVersionHasThem(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	p := issuePublisher(t, srv, saga.PublisherConfig{Children: saga.ChildrenActions})
	gh.refuse["POST /repos/acme/app/issues/1/sub_issues"] = ghRefusal{status: http.StatusNotFound}

	err := p.PublishRun(context.Background(), onMain(twoRules()), nil)
	if err == nil || !strings.Contains(err.Error(), "Sub-issues need GitHub.com or GitHub Enterprise Server 3.18 or later") {
		t.Fatalf("err = %v", err)
	}
	if c := gh.issue(2); c.State != "closed" {
		t.Errorf("the unlinked child is %s, want closed", c.State)
	}
}

func TestGitLabMakesEachChildATaskOfItsParent(t *testing.T) {
	gl, srv := newFakeGitLab(t)
	p := gitlabIssues(t, srv, saga.PublisherConfig{Children: saga.ChildrenActions})
	publishGitLab(t, p, onMain(twoRules()))

	if parent := gl.issue(1); parent.Type != "issue" || parent.Parent != 0 {
		t.Errorf("parent = %+v", parent)
	}
	for _, n := range []int64{2, 3} {
		if c := gl.issue(n); c.Type != "task" || c.Parent != 1 {
			t.Errorf("child #%d: type %q, parent %d", n, c.Type, c.Parent)
		}
	}
	for i, r := range gl.requests {
		if strings.HasSuffix(r, "/api/graphql") && gl.tokens[i] != "secret" {
			t.Errorf("GraphQL sent without the token")
		}
	}

	publishGitLab(t, p, onMain(map[string][]sarif.Result{"sca": {
		codeFinding("api", "r1", "P2", "a.go"),
		codeFinding("api", "r2", "P1", "b.go"),
	}}))
	if got := gl.issue(2).Title; got != "P2 · Fix r1" {
		t.Errorf("retitled child = %q", got)
	}
}

func TestAGitLabParentThatCannotBeSetClosesTheTask(t *testing.T) {
	for name, set := range map[string]func(*fakeGitLab){
		"top-level": func(f *fakeGitLab) { f.graphqlErrors = []string{"Field 'workItemUpdate' doesn't exist"} },
		"mutation":  func(f *fakeGitLab) { f.workItemErrors = []string{"cannot be added to an issue"} },
	} {
		t.Run(name, func(t *testing.T) {
			gl, srv := newFakeGitLab(t)
			set(gl)
			p := gitlabIssues(t, srv, saga.PublisherConfig{Children: saga.ChildrenActions})
			err := p.PublishRun(context.Background(), onMain(twoRules()), nil)
			if err == nil || !strings.Contains(err.Error(), "make #2 a child of #1") {
				t.Fatalf("err = %v", err)
			}
			if c := gl.issue(2); c.State != "closed" {
				t.Errorf("the task with no parent is %s, want closed", c.State)
			}
		})
	}
}

func TestGitLabGraphQLIsBesideTheRESTRoot(t *testing.T) {
	_, srv := newFakeGitLab(t)
	p := gitlabIssues(t, srv, saga.PublisherConfig{})
	if got, want := p.graphqlURL(), srv.URL+"/api/graphql"; got != want {
		t.Errorf("graphqlURL = %q, want %q", got, want)
	}
	t.Setenv("CI_API_GRAPHQL_URL", "https://gitlab.test/api/graphql")
	if got := p.graphqlURL(); got != "https://gitlab.test/api/graphql" {
		t.Errorf("graphqlURL = %q, want the runner's", got)
	}
}

func TestAzureLinksEachChildTaskToARequirementParent(t *testing.T) {
	az, srv := newFakeAzure(t)
	cfg := saga.PublisherConfig{Children: saga.ChildrenActions,
		Item: &saga.IssueItem{Fields: map[string]string{"Custom.Team": "payments"}}}
	publishAzure(t, srv, cfg, azureCI(twoRules()))

	parent := az.item(1)
	if parent.Type != "User Story" || parent.Fields["Custom.Team"] != "payments" {
		t.Errorf("parent: type %q, fields %v", parent.Type, parent.Fields)
	}
	for _, n := range []int64{2, 3} {
		c := az.item(n)
		if c.Type != "Task" || c.Parent != 1 || c.Fields["Custom.Team"] != nil {
			t.Errorf("child #%d: type %q, parent %d, fields %v", n, c.Type, c.Parent, c.Fields)
		}
		if !strings.HasPrefix(c.ParentURL, srv.URL+"/acme/_apis/wit/workItems/") {
			t.Errorf("child #%d linked by %q", n, c.ParentURL)
		}
	}

	// r1 falls to P2 and r2 rises to P1 in a later run, which is a fresh process.
	publishAzure(t, srv, cfg, azureCI(map[string][]sarif.Result{"sca": {
		codeFinding("api", "r1", "P2", "a.go"),
		codeFinding("api", "r2", "P1", "b.go"),
	}}))
	if got := az.item(2).Title; got != "P2 · Fix r1" {
		t.Errorf("retitled child = %q", got)
	}
}

func TestAnAzureItemTypeNamesTheParentOnly(t *testing.T) {
	az, srv := newFakeAzure(t)
	publishAzure(t, srv, saga.PublisherConfig{Children: saga.ChildrenControls, Item: &saga.IssueItem{Type: "Bug"}},
		azureCI(twoRules()))
	if p, c := az.item(1), az.item(2); p.Type != "Bug" || c.Type != "Task" || c.Parent != 1 {
		t.Errorf("parent %q, child %q under %d", p.Type, c.Type, c.Parent)
	}
}

func TestAPacedClientAffordsWritesWithinItsBudget(t *testing.T) {
	now := time.Unix(0, 0)
	pace := &pacing{maxWait: issueMaxWait, budget: 10 * time.Second, writeGap: time.Second, now: func() time.Time { return now }}
	c := &http.Client{Transport: &retryTransport{pace: pace}}
	if !clientAffords(c, 10) || clientAffords(c, 11) {
		t.Errorf("a 10s budget at 1s a write: affords 10 %v, 11 %v", clientAffords(c, 10), clientAffords(c, 11))
	}
	pace.notBefore = now.Add(5 * time.Second)
	if clientAffords(c, 6) {
		t.Error("an announced 5s delay is not counted against the budget")
	}
	if !clientAffords(nil, 1000) || !clientAffords(&http.Client{}, 1000) {
		t.Error("an unpaced client has a budget")
	}
}
