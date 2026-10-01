//go:build integration

package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The children tests take a parent and its children through a run that opens them, a run whose
// lower action is gone, and a run that passes, against each forge. The fakes link a child the way
// each forge is documented to; these are the check that the forge accepts the link from the
// credential the docs describe and reports it back as the child's parent.

// onlyR1 is twoRules with the P2 action gone.
func onlyR1() map[string][]sarif.Result {
	return map[string][]sarif.Result{"sca": {codeFinding("api", "r1", "P1", "a.go")}}
}

// isChild reports whether a body carries a child's marker.
func isChild(body string) bool {
	return strings.Contains(body, " action=") || strings.Contains(body, " child=")
}

func TestLiveGitHubChildren(t *testing.T) {
	g := newLiveGitHub(t)
	p := g.publisher(saga.PublisherConfig{Children: saga.ChildrenActions})

	g.mustPublish(p, g.onMain(twoRules()))
	var parent int64
	for _, i := range g.openCount(3) {
		if !isChild(i.Body) {
			parent = i.Number
		}
	}
	if parent == 0 {
		t.Fatal("no open issue is the parent")
	}
	var subs []struct {
		Number int64  `json:"number"`
		Title  string `json:"title"`
	}
	g.api(http.MethodGet, "issues/"+strconv.FormatInt(parent, 10)+"/sub_issues", nil, &subs)
	titles := map[string]int64{}
	for _, s := range subs {
		titles[s.Title] = s.Number
	}
	if len(subs) != 2 || titles["P1 · Fix r1"] == 0 || titles["P2 · Fix r2"] == 0 {
		t.Fatalf("sub-issues of #%d = %+v, want P1 · Fix r1 and P2 · Fix r2", parent, subs)
	}

	g.mustPublish(p, g.onMain(onlyR1()))
	r2 := titles["P2 · Fix r2"]
	if i := g.issue(r2); i.State != "closed" {
		t.Errorf("#%d is %s after its action left the run", r2, i.State)
	}
	if cs := g.comments(r2); len(cs) != 1 || cs[0] != "The run no longer reports this action." {
		t.Errorf("#%d comments = %q", r2, cs)
	}

	g.openCount(2)
	g.mustPublish(p, g.onMain(map[string][]sarif.Result{"sca": nil}))
	for _, n := range []int64{titles["P1 · Fix r1"], parent} {
		if i := g.issue(n); i.State != "closed" {
			t.Errorf("#%d is %s after the gate passed", n, i.State)
		}
	}
}

// graphql posts a query to gitlab.com's GraphQL endpoint with the sandbox token.
func (g *liveGitLab) graphql(body, out any) {
	g.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		g.t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		strings.TrimSuffix(liveGitLabAPI, "v4/")+"graphql", bytes.NewReader(b))
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
		g.t.Fatalf("GraphQL: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		g.t.Fatal(err)
	}
}

// gitlabParent is the iid of a work item's parent, read through GraphQL, where GitLab keeps the
// hierarchy; 0 when it has none.
func (g *liveGitLab) gitlabParent(id int64) int64 {
	g.t.Helper()
	req := map[string]any{
		"query":     `query($id: WorkItemID!) { workItem(id: $id) { widgets { ... on WorkItemWidgetHierarchy { parent { iid } } } } }`,
		"variables": map[string]string{"id": "gid://gitlab/WorkItem/" + strconv.FormatInt(id, 10)},
	}
	var out struct {
		Data struct {
			WorkItem struct {
				Widgets []struct {
					Parent *struct {
						IID string `json:"iid"`
					} `json:"parent"`
				} `json:"widgets"`
			} `json:"workItem"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	g.graphql(req, &out)
	if len(out.Errors) > 0 {
		g.t.Fatalf("GraphQL: %s", out.Errors[0].Message)
	}
	for _, w := range out.Data.WorkItem.Widgets {
		if w.Parent != nil {
			n, err := strconv.ParseInt(w.Parent.IID, 10, 64)
			if err != nil {
				g.t.Fatal(err)
			}
			return n
		}
	}
	return 0
}

func TestLiveGitLabChildren(t *testing.T) {
	g := newLiveGitLab(t)
	p := g.publisher(saga.PublisherConfig{Children: saga.ChildrenActions})

	g.mustPublish(p, g.onMain(twoRules()))
	open := g.openCount(3)
	var parent int64
	kids := map[string]liveGitLabIssue{}
	for _, i := range open {
		if isChild(i.Description) {
			kids[i.Title] = i
		} else {
			parent = i.IID
		}
	}
	if parent == 0 || len(kids) != 2 {
		t.Fatalf("open = %+v, want a parent and two children", open)
	}
	for _, title := range []string{"P1 · Fix r1", "P2 · Fix r2"} {
		k, ok := kids[title]
		if !ok {
			t.Fatalf("no child titled %q among %v", title, slices.Collect(maps.Keys(kids)))
		}
		if k.IssueType != "task" {
			t.Errorf("#%d is a %s, want a task", k.IID, k.IssueType)
		}
		if got := g.gitlabParent(k.ID); got != parent {
			t.Errorf("#%d has parent #%d, want #%d", k.IID, got, parent)
		}
	}

	g.mustPublish(p, g.onMain(onlyR1()))
	r2 := kids["P2 · Fix r2"].IID
	if i := g.issue(r2); i.State != "closed" {
		t.Errorf("#%d is %s after its action left the run", r2, i.State)
	}
	if ns := g.notes(r2); !slices.Contains(ns, "The run no longer reports this action.") {
		t.Errorf("#%d notes = %q", r2, ns)
	}

	g.openCount(2)
	g.mustPublish(p, g.onMain(map[string][]sarif.Result{"sca": nil}))
	for _, n := range []int64{kids["P1 · Fix r1"].IID, parent} {
		if i := g.issue(n); i.State != "closed" {
			t.Errorf("#%d is %s after the gate passed", n, i.State)
		}
	}
}

// azureParent is the id of a work item's parent, from its hierarchy relation; 0 when it has none.
func (a *liveAzure) azureParent(id int64) int64 {
	a.t.Helper()
	var w struct {
		Relations []struct {
			Rel string `json:"rel"`
			URL string `json:"url"`
		} `json:"relations"`
	}
	a.api(http.MethodGet, "wit/workitems/"+strconv.FormatInt(id, 10)+"?$expand=relations&api-version=7.1", "", nil, &w)
	for _, r := range w.Relations {
		if r.Rel == "System.LinkTypes.Hierarchy-Reverse" {
			n, err := strconv.ParseInt(r.URL[strings.LastIndex(r.URL, "/")+1:], 10, 64)
			if err != nil {
				a.t.Fatal(err)
			}
			return n
		}
	}
	return 0
}

func TestLiveAzureChildren(t *testing.T) {
	a := newLiveAzure(t)
	p := a.publisher(saga.PublisherConfig{Children: saga.ChildrenActions})

	a.mustPublish(p, a.onMain(twoRules()))
	open := a.openCount(3)
	var parent int64
	kids := map[string]int64{}
	for _, i := range open {
		if isChild(i.Fields.Description) {
			kids[i.Fields.Title] = i.ID
		} else {
			parent = i.ID
		}
	}
	if parent == 0 || kids["P1 · Fix r1"] == 0 || kids["P2 · Fix r2"] == 0 {
		t.Fatalf("open = %d items, parent %d, children %v", len(open), parent, kids)
	}
	for title, id := range kids {
		if got := a.azureParent(id); got != parent {
			t.Errorf("%q (#%d) has parent #%d, want #%d", title, id, got, parent)
		}
	}

	a.mustPublish(p, a.onMain(onlyR1()))
	r2 := kids["P2 · Fix r2"]
	if i := a.item(r2); a.category(i.Fields.Type, i.Fields.State) != "Completed" {
		t.Errorf("#%d is %s after its action left the run", r2, i.Fields.State)
	}
	if cs := a.comments(r2); !slices.ContainsFunc(cs, func(c string) bool { return strings.Contains(c, "no longer reports this action") }) {
		t.Errorf("#%d comments = %q", r2, cs)
	}

	a.openCount(2)
	a.mustPublish(p, a.onMain(map[string][]sarif.Result{"sca": nil}))
	for _, n := range []int64{kids["P1 · Fix r1"], parent} {
		if i := a.item(n); a.category(i.Fields.Type, i.Fields.State) != "Completed" {
			t.Errorf("#%d is %s after the gate passed", n, i.Fields.State)
		}
	}
}
