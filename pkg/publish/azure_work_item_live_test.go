//go:build integration

package publish

import (
	"bytes"
	"context"
	"encoding/base64"
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

// The organization and project the live test writes work items to, and a personal access token
// with Work Items: Read & Write. The project should be one nobody reads: every run opens and
// closes work items in it.
//
// #nosec G101 -- the names of environment variables, not their values.
const (
	liveAzureTokenEnv   = "SANDBOX_AZURE_TOKEN"
	liveAzureOrgEnv     = "SANDBOX_AZURE_ORG_URL"
	liveAzureProjectEnv = "SANDBOX_AZURE_PROJECT"
)

// liveAzure is the sandbox project, read and written with Azure DevOps' own API rather than
// through the publisher, so what the test asserts is what Azure holds.
type liveAzure struct {
	t                   *testing.T
	org, project, token string
	name                string
	run                 int
}

type liveAzureItem struct {
	ID     int64 `json:"id"`
	Rev    int   `json:"rev"`
	Fields struct {
		Type        string          `json:"System.WorkItemType"`
		Title       string          `json:"System.Title"`
		State       string          `json:"System.State"`
		Description string          `json:"System.Description"`
		Tags        string          `json:"System.Tags"`
		Priority    int             `json:"Microsoft.VSTS.Common.Priority"`
		Activity    string          `json:"Microsoft.VSTS.Common.Activity"`
		AssignedTo  json.RawMessage `json:"System.AssignedTo"`
	} `json:"fields"`
	Formats map[string]string `json:"multilineFieldsFormat"`
}

func (i liveAzureItem) tags() []string { return splitTags(i.Fields.Tags) }

// newLiveAzure skips unless a sandbox project and a token for it are configured. Each test names
// its own Draugr project, so its markers match no work item another run or another test left open.
func newLiveAzure(t *testing.T) *liveAzure {
	t.Helper()
	token, org, project := os.Getenv(liveAzureTokenEnv), os.Getenv(liveAzureOrgEnv), os.Getenv(liveAzureProjectEnv)
	if token == "" || org == "" || project == "" {
		t.Skipf("set %s, %s and %s to drive the azure-work-item publisher against a real project",
			liveAzureTokenEnv, liveAzureOrgEnv, liveAzureProjectEnv)
	}
	a := &liveAzure{t: t, org: strings.TrimSuffix(org, "/") + "/", project: project, token: token,
		name: fmt.Sprintf("live-%s-%d", strings.ToLower(t.Name()), time.Now().UnixNano())}
	t.Cleanup(a.closeLeftovers)
	return a
}

// call sends one request to the organization, relative to its root, and fails the test on
// anything but a success.
func (a *liveAzure) call(method, path, contentType string, body, out any) {
	a.t.Helper()
	r := bytes.NewReader(nil)
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			a.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, a.org+path, r)
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+a.token)))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		a.t.Fatalf("%s %s: %s", method, path, resp.Status)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			a.t.Fatal(err)
		}
	}
}

// api sends one request to the project's API.
func (a *liveAzure) api(method, path, contentType string, body, out any) {
	a.t.Helper()
	a.call(method, url.PathEscape(a.project)+"/_apis/"+path, contentType, body, out)
}

// open lists this test's open work items, oldest first, found by the tracking tag the publisher
// queries and the project in their marker.
func (a *liveAzure) open() []liveAzureItem {
	a.t.Helper()
	var found struct {
		WorkItems []struct {
			ID int64 `json:"id"`
		} `json:"workItems"`
	}
	q := "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS " +
		wiqlString(liveLabel) + " AND [System.State] <> 'Closed' AND [System.State] <> 'Removed' ORDER BY [System.Id]"
	a.api(http.MethodPost, "wit/wiql?api-version=7.1", "application/json", map[string]string{"query": q}, &found)
	var mine []liveAzureItem
	for _, w := range found.WorkItems {
		if i := a.item(w.ID); strings.Contains(i.Fields.Description, "project="+a.name+" ") {
			mine = append(mine, i)
		}
	}
	return mine
}

// openCount polls until n work items are open. A query can trail a write, and a run that reads it
// early misses the item it just opened.
func (a *liveAzure) openCount(n int) []liveAzureItem {
	a.t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		open := a.open()
		if len(open) == n {
			return open
		}
		if time.Now().After(deadline) {
			a.t.Fatalf("the open work items never numbered %d: %d open", n, len(open))
		}
		time.Sleep(3 * time.Second)
	}
}

func (a *liveAzure) item(n int64) liveAzureItem {
	a.t.Helper()
	var i liveAzureItem
	a.api(http.MethodGet, "wit/workitems/"+strconv.FormatInt(n, 10)+"?api-version=7.1", "", nil, &i)
	return i
}

func (a *liveAzure) set(n int64, field string, value any) {
	a.t.Helper()
	a.api(http.MethodPatch, "wit/workitems/"+strconv.FormatInt(n, 10)+"?api-version=7.1", "application/json-patch+json",
		[]patchOp{{Op: "add", Path: "/fields/" + field, Value: value}}, nil)
}

// comments are the Markdown the comments on a work item were written from, oldest first.
func (a *liveAzure) comments(n int64) []string {
	a.t.Helper()
	var got struct {
		Comments []struct {
			Text string `json:"text"`
		} `json:"comments"`
	}
	a.api(http.MethodGet, "wit/workItems/"+strconv.FormatInt(n, 10)+"/comments?order=asc&api-version=7.1-preview.4", "", nil, &got)
	out := make([]string, 0, len(got.Comments))
	for _, c := range got.Comments {
		out = append(out, azureIn(c.Text))
	}
	return out
}

// category is the state category a state of a type maps to.
func (a *liveAzure) category(itemType, state string) string {
	a.t.Helper()
	var got struct {
		Value []struct {
			Name     string `json:"name"`
			Category string `json:"category"`
		} `json:"value"`
	}
	a.api(http.MethodGet, "wit/workitemtypes/"+url.PathEscape(itemType)+"/states?api-version=7.1", "", nil, &got)
	for _, s := range got.Value {
		if s.Name == state {
			return s.Category
		}
	}
	return ""
}

// me is the account the token belongs to, an identity the organization can assign a work item to.
func (a *liveAzure) me() string {
	a.t.Helper()
	var got struct {
		AuthenticatedUser struct {
			Properties struct {
				Account struct {
					Value string `json:"$value"`
				} `json:"Account"`
			} `json:"properties"`
		} `json:"authenticatedUser"`
	}
	a.call(http.MethodGet, "_apis/connectionData", "", nil, &got)
	if got.AuthenticatedUser.Properties.Account.Value == "" {
		a.t.Fatal("connectionData names no account for the token")
	}
	return got.AuthenticatedUser.Properties.Account.Value
}

// closeLeftovers closes whatever this test left open, so a failed run does not leave the next one
// reading its work items.
func (a *liveAzure) closeLeftovers() {
	for _, i := range a.open() {
		a.set(i.ID, "System.State", "Closed")
	}
}

// publisher is the azure-work-item publisher as an Azure Pipelines job would build it, against the
// sandbox.
func (a *liveAzure) publisher(cfg saga.PublisherConfig) *azureWorkItemPublisher {
	a.t.Helper()
	a.t.Setenv("TF_BUILD", "True")
	a.t.Setenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", a.org)
	a.t.Setenv("SYSTEM_TEAMPROJECT", a.project)
	a.t.Setenv("SYSTEM_ACCESSTOKEN", a.token)
	a.t.Setenv("BUILD_REPOSITORY_ID", "")
	cfg.Kind = "azure-work-item"
	cfg.Label = liveLabel
	p, err := For(cfg)
	if err != nil {
		a.t.Fatal(err)
	}
	ap, ok := p.(*azureWorkItemPublisher)
	if !ok {
		a.t.Fatalf("publisher is %T", p)
	}
	return ap
}

// onMain is a run of this test's project on the default branch, in a build numbered by how many
// runs the test has made.
func (a *liveAzure) onMain(controls map[string][]sarif.Result) report.Data {
	a.run++
	d := runOver(controls)
	d.Project = a.name
	id := strconv.Itoa(a.run)
	d.CI = &ci.Context{Branch: "main", DefaultBranch: "main", RunID: id,
		URL: a.org + url.PathEscape(a.project) + "/_build/results?buildId=" + id}
	return d
}

func (a *liveAzure) mustPublish(p *azureWorkItemPublisher, data report.Data) {
	a.t.Helper()
	if err := p.PublishRun(context.Background(), data, nil); err != nil {
		a.t.Fatal(err)
	}
}

// TestLiveAzureWorkItemLifecycle takes one work item through everything a run can do to it,
// against a real project: open it with its metadata, leave it alone, rewrite it, restore a tag
// removed by hand, close a duplicate somebody opened, ignore a pull request, and close it when the
// gate passes.
//
// The fake in azure_work_item_test.go answers the way the sandbox answered a probe. This is the
// check that Azure DevOps still answers that way: that it stores the description as Markdown, that
// its sanitizer changes nothing an unchanged run would rewrite, markup in scanner text included,
// that it keeps every tag, the priority, the assignee and an extra field, and that the token may
// comment and close.
func TestLiveAzureWorkItemLifecycle(t *testing.T) {
	a := newLiveAzure(t)
	assignee := a.me()
	priority := 1
	p := a.publisher(saga.PublisherConfig{Item: &saga.IssueItem{
		Tags: []string{"triage"}, AssignedTo: assignee, Priority: &priority,
		Fields: map[string]string{"Microsoft.VSTS.Common.Activity": "Development"},
	}})

	hostile := upgradeFinding("api", "CVE-2026-0001", "P1")
	hostile.Message = `openssl <b>1.1.1</b> "q" & 'y' a<b <!-- c -->`
	failing := map[string][]sarif.Result{"sca": {hostile}}
	a.mustPublish(p, a.onMain(failing))
	first := a.openCount(1)[0]
	for _, want := range []string{liveLabel, "triage", "draugr:priority:P1"} {
		if !containsFold(first.tags(), want) {
			t.Errorf("tags = %q, want %s", first.tags(), want)
		}
	}
	if first.Fields.Type != "Task" {
		t.Errorf("type = %q, want Task, the Task category's default", first.Fields.Type)
	}
	if first.Fields.Priority != 1 {
		t.Errorf("priority = %d, want 1", first.Fields.Priority)
	}
	if first.Fields.Activity != "Development" {
		t.Errorf("activity = %q, want Development", first.Fields.Activity)
	}
	if !strings.Contains(string(first.Fields.AssignedTo), assignee) {
		t.Errorf("assignedTo = %s, want %s", first.Fields.AssignedTo, assignee)
	}
	if !strings.EqualFold(first.Formats["System.Description"], "markdown") {
		t.Errorf("multilineFieldsFormat = %v, want the description in Markdown", first.Formats)
	}
	if !strings.HasPrefix(azureIn(first.Fields.Description), "<!-- draugr:issue v1 project="+a.name+" ") {
		t.Errorf("the description lost the marker:\n%s", first.Fields.Description)
	}

	// The same findings again: the body names the run that last changed it, so nothing is written.
	a.mustPublish(p, a.onMain(failing))
	if again := a.item(first.ID); again.Rev != first.Rev {
		t.Errorf("an unchanged run wrote %d (rev %d, was %d)", first.ID, again.Rev, first.Rev)
	}

	// Another finding: the description is rewritten in place, and nobody gets a comment.
	failing["sast"] = []sarif.Result{codeFinding("api", "python.lang.eval", "P1", "app/app.py")}
	a.mustPublish(p, a.onMain(failing))
	rewritten := a.item(first.ID)
	if rewritten.Rev == first.Rev || !strings.Contains(rewritten.Fields.Description, "python.lang.eval") {
		t.Errorf("%d was not rewritten with the new finding", first.ID)
	}
	if cs := a.comments(first.ID); len(cs) != 0 {
		t.Errorf("a rewrite commented on %d: %q", first.ID, cs)
	}

	// A fact tag removed by hand comes back; the tracking tag is what finds the item, so it stays on.
	kept := slices.DeleteFunc(rewritten.tags(), func(s string) bool { return strings.EqualFold(s, "draugr:priority:P1") })
	a.set(first.ID, "System.Tags", strings.Join(kept, "; "))
	a.mustPublish(p, a.onMain(failing))
	if i := a.item(first.ID); !containsFold(i.tags(), "draugr:priority:P1") {
		t.Errorf("after triage: tags %q, want draugr:priority:P1 back", i.tags())
	}

	// Somebody opens a second item carrying the same marker. The newer one closes against the older.
	var dup liveAzureItem
	a.api(http.MethodPost, "wit/workitems/$Task?api-version=7.1", "application/json-patch+json", []patchOp{
		{Op: "add", Path: "/fields/System.Title", Value: "copy"},
		{Op: "add", Path: "/fields/System.Description", Value: rewritten.Fields.Description},
		{Op: "add", Path: "/fields/System.Tags", Value: liveLabel},
	}, &dup)
	a.openCount(2)
	a.mustPublish(p, a.onMain(failing))
	if i := a.item(dup.ID); a.category(i.Fields.Type, i.Fields.State) != azureCompleted {
		t.Errorf("duplicate %d = %s, want a Completed state", dup.ID, i.Fields.State)
	}
	id := strconv.FormatInt(first.ID, 10)
	link := "[#" + id + "](" + a.org + url.PathEscape(a.project) + "/_workitems/edit/" + id + ")"
	if cs := a.comments(dup.ID); len(cs) != 1 || !strings.Contains(cs[0], "Duplicate of ") || !strings.Contains(cs[0], link) {
		t.Errorf("duplicate comments = %q, want a link to %d", cs, first.ID)
	}

	a.openCount(1)

	// A pull request that fixes everything is judged on changes nobody has merged.
	pr := a.onMain(map[string][]sarif.Result{"sca": nil})
	pr.CI.PullRequest = true
	a.mustPublish(p, pr)
	if i := a.item(first.ID); a.category(i.Fields.Type, i.Fields.State) == azureCompleted {
		t.Errorf("a pull-request run closed %d", first.ID)
	}

	a.mustPublish(p, a.onMain(map[string][]sarif.Result{"sca": nil}))
	if i := a.item(first.ID); a.category(i.Fields.Type, i.Fields.State) != azureCompleted {
		t.Errorf("%d = %s, want a Completed state", first.ID, i.Fields.State)
	}
	job := "[job " + strconv.Itoa(a.run) + "]("
	if cs := a.comments(first.ID); len(cs) != 1 || !strings.Contains(cs[0], "The gate passes on `main`") || !strings.Contains(cs[0], job) {
		t.Errorf("closing comments = %q, want the gate passing in job %d", cs, a.run)
	}
}

// TestLiveAzureUnknownAssigneeIsNamed asks for an assignee the organization does not know. The run
// names the key that set it, and opens nothing.
func TestLiveAzureUnknownAssigneeIsNamed(t *testing.T) {
	a := newLiveAzure(t)
	nobody := "draugr-no-such-user-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "@example.invalid"
	p := a.publisher(saga.PublisherConfig{Item: &saga.IssueItem{AssignedTo: nobody}})
	err := p.PublishRun(context.Background(), a.onMain(map[string][]sarif.Result{"sca": {upgradeFinding("api", "CVE-2026-0001", "P1")}}), nil)
	if err == nil || !strings.Contains(err.Error(), "item.assignedTo") {
		t.Fatalf("err = %v, want it to name item.assignedTo", err)
	}
	if n := len(a.open()); n != 0 {
		t.Errorf("open work items = %d, want none", n)
	}
}
