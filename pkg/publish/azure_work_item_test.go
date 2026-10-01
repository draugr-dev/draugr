package publish

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// azItem is one work item as the fake Azure DevOps holds it.
type azItem struct {
	ID          int64
	Rev         int
	Project     string
	Type, State string
	Title       string
	Description string
	// Format is the description's multilineFieldsFormat, empty for HTML.
	Format   string
	Tags     []string
	Fields   map[string]any
	Comments []azComment
	// Parent is the id of the item it is a child of, and ParentURL the address it was linked by.
	Parent    int64
	ParentURL string
}

// azComment is a comment and the format it was posted in.
type azComment struct{ Text, Format string }

// said is the Markdown each comment was written from.
func (i *azItem) said() []string {
	out := make([]string, len(i.Comments))
	for n, c := range i.Comments {
		out[n] = azureIn(c.Text)
	}
	return out
}

// fakeAzure answers the work-item endpoints of the acme collection from memory, for any project in
// it, and records every request. It stores a description the way Azure does, through an HTML
// sanitizer whatever its format.
type fakeAzure struct {
	t        *testing.T
	mu       sync.Mutex
	items    map[int64]*azItem
	next     int64
	requests []string
	bodies   [][]patchOp // every JSON Patch, in order
	auth     []string

	// states is each type's states and their categories, as the process defines them.
	states map[string][][2]string
	// statesSeparately answers the type list without states, as some processes do.
	statesSeparately bool
	defaultBranch    string
	// dropTags answers a create without its tags.
	dropTags bool
	// refuse answers every request whose "METHOD path" starts with the key with the status and body.
	refuse map[string]azRefusal
}

type azRefusal struct {
	status int
	body   string
}

const azProject = "/acme/Shop%20App/_apis/"

func newFakeAzure(t *testing.T) (*fakeAzure, *httptest.Server) {
	t.Helper()
	f := &fakeAzure{t: t, items: map[int64]*azItem{}, next: 1, refuse: map[string]azRefusal{}, defaultBranch: "refs/heads/main",
		states: map[string][][2]string{
			"Task":       {{"New", "Proposed"}, {"Active", "InProgress"}, {"Closed", "Completed"}, {"Removed", "Removed"}},
			"User Story": {{"New", "Proposed"}, {"Active", "InProgress"}, {"Resolved", "InProgress"}, {"Closed", "Completed"}},
			"Bug":        {{"New", "Proposed"}, {"Resolved", "Completed"}, {"Closed", "Completed"}},
		}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAzure) add(i azItem) *azItem {
	f.mu.Lock()
	defer f.mu.Unlock()
	i.ID = f.next
	f.next++
	i.Rev = 1
	if i.Project == "" {
		i.Project = "Shop App"
	}
	if i.Type == "" {
		i.Type = "Task"
	}
	if i.State == "" {
		i.State = "New"
	}
	i.Description = azSanitize(i.Description)
	f.items[i.ID] = &i
	return &i
}

func (f *fakeAzure) item(n int64) *azItem {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.items[n]
}

func (f *fakeAzure) open() []*azItem {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*azItem
	for n := int64(1); n < f.next; n++ {
		if i := f.items[n]; i != nil && f.category(i) != azureCompleted && f.category(i) != azureRemoved {
			out = append(out, i)
		}
	}
	return out
}

func (f *fakeAzure) category(i *azItem) string {
	for _, s := range f.states[i.Type] {
		if s[0] == i.State {
			return s[1]
		}
	}
	return ""
}

func (f *fakeAzure) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if !strings.HasPrefix(r, "GET ") && !strings.Contains(r, "/wiql") {
			out = append(out, r)
		}
	}
	return out
}

var (
	azHTMLComment = regexp.MustCompile(`<!--.*?-->`)
	azCloseTags   = regexp.MustCompile(`</(p|h3|td|li|ul|summary|details)>`)
	azEntities    = strings.NewReplacer("&#34;", "&quot;", "&#39;", "'")
)

// azSanitize is what Azure DevOps does to a description or comment it stores: HTML comments
// removed, a space added before some closing tags, and entities spelled its own way.
func azSanitize(s string) string {
	s = azHTMLComment.ReplaceAllString(s, "")
	return azEntities.Replace(azCloseTags.ReplaceAllString(s, " </$1>"))
}

func azTags(tags []string) string {
	sorted := slices.Clone(tags)
	sort.Slice(sorted, func(i, j int) bool { return strings.ToLower(sorted[i]) < strings.ToLower(sorted[j]) })
	return strings.Join(sorted, "; ")
}

func (f *fakeAzure) wire(i *azItem) map[string]any {
	fields := map[string]any{"System.WorkItemType": i.Type, "System.State": i.State, "System.Title": i.Title,
		"System.Description": i.Description, "System.Tags": azTags(i.Tags)}
	for k, v := range i.Fields {
		fields[k] = v
	}
	out := map[string]any{"id": i.ID, "rev": i.Rev, "fields": fields}
	if i.Format != "" {
		out["multilineFieldsFormat"] = map[string]string{"System.Description": strings.ToLower(i.Format)}
	}
	return out
}

func (f *fakeAzure) fail(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body)) // #nosec G705 -- a fake server answering the test's own requests
}

var (
	wiqlTag   = regexp.MustCompile(`CONTAINS '((?:[^']|'')*)'`)
	wiqlNotIn = regexp.MustCompile(`NOT IN \(([^)]*)\)`)
)

func (f *fakeAzure) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := r.Method + " " + r.URL.EscapedPath()
	f.requests = append(f.requests, line)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	for prefix, refusal := range f.refuse {
		if strings.HasPrefix(line, prefix) {
			f.fail(w, refusal.status, refusal.body)
			return
		}
	}
	project, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.EscapedPath(), "/acme/"), "/_apis/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	project, _ = url.PathUnescape(project)
	var ops []patchOp
	var in map[string]any
	if r.Method != http.MethodGet {
		if r.Header.Get("Content-Type") == "application/json-patch+json" {
			_ = json.NewDecoder(r.Body).Decode(&ops)
			f.bodies = append(f.bodies, ops)
		} else {
			_ = json.NewDecoder(r.Body).Decode(&in)
		}
	}
	enc := json.NewEncoder(w)
	switch {
	case r.Method == http.MethodGet && rest == "wit/workitemtypes":
		var types []map[string]any
		for name, states := range f.states {
			var ss []map[string]string
			if !f.statesSeparately {
				for _, s := range states {
					ss = append(ss, map[string]string{"name": s[0], "category": s[1]})
				}
			}
			types = append(types, map[string]any{"name": name, "states": ss})
		}
		_ = enc.Encode(map[string]any{"value": types})
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "wit/workitemtypes/") && strings.HasSuffix(rest, "/states"):
		name, _ := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(rest, "wit/workitemtypes/"), "/states"))
		var ss []map[string]string
		for _, s := range f.states[name] {
			ss = append(ss, map[string]string{"name": s[0], "category": s[1]})
		}
		_ = enc.Encode(map[string]any{"value": ss})
	case r.Method == http.MethodGet && rest == "wit/workitemtypecategories/Microsoft.TaskCategory":
		_ = enc.Encode(map[string]any{"defaultWorkItemType": map[string]string{"name": "Task"}})
	case r.Method == http.MethodGet && rest == "wit/workitemtypecategories/Microsoft.RequirementCategory":
		_ = enc.Encode(map[string]any{"defaultWorkItemType": map[string]string{"name": "User Story"}})
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "git/repositories/"):
		_ = enc.Encode(map[string]string{"defaultBranch": f.defaultBranch})
	case r.Method == http.MethodPost && rest == "wit/wiql":
		q, _ := in["query"].(string)
		tag := strings.ReplaceAll(wiqlTag.FindStringSubmatch(q)[1], "''", "'")
		var closed []string
		if m := wiqlNotIn.FindStringSubmatch(q); m != nil {
			for _, s := range strings.Split(m[1], ",") {
				closed = append(closed, strings.Trim(strings.TrimSpace(s), "'"))
			}
		}
		var found []map[string]int64
		for n := int64(1); n < f.next; n++ {
			i := f.items[n]
			if i == nil || i.Project != project || slices.Contains(closed, i.State) {
				continue
			}
			// CONTAINS matches a tag by prefix, which is what a longer tag makes the publisher filter.
			for _, t := range i.Tags {
				if strings.HasPrefix(strings.ToLower(t), strings.ToLower(tag)) {
					found = append(found, map[string]int64{"id": i.ID})
					break
				}
			}
		}
		_ = enc.Encode(map[string]any{"workItems": found})
	case r.Method == http.MethodGet && rest == "wit/workitems":
		var out []map[string]any
		for _, s := range strings.Split(r.URL.Query().Get("ids"), ",") {
			n, _ := strconv.ParseInt(s, 10, 64)
			if i := f.items[n]; i != nil {
				out = append(out, f.wire(i))
			}
		}
		_ = enc.Encode(map[string]any{"value": out})
	case r.Method == http.MethodPost && strings.HasPrefix(rest, "wit/workitems/$"):
		itemType, _ := url.PathUnescape(strings.TrimPrefix(rest, "wit/workitems/$"))
		if _, known := f.states[itemType]; !known {
			f.fail(w, http.StatusNotFound, `{"message":"VS402323: Work item type `+itemType+` does not exist."}`)
			return
		}
		i := &azItem{ID: f.next, Rev: 1, Project: project, Type: itemType, State: f.states[itemType][0][0], Fields: map[string]any{}}
		f.next++
		f.apply(i, ops)
		if f.dropTags {
			i.Tags = nil
		}
		f.items[i.ID] = i
		_ = enc.Encode(f.wire(i))
	case r.Method == http.MethodPatch && strings.HasPrefix(rest, "wit/workitems/"):
		n, _ := strconv.ParseInt(strings.TrimPrefix(rest, "wit/workitems/"), 10, 64)
		i := f.items[n]
		if i == nil {
			f.fail(w, http.StatusNotFound, `{"message":"TF401232: Work item does not exist"}`)
			return
		}
		for _, op := range ops {
			if op.Op == "test" && op.Path == "/rev" && int(op.Value.(float64)) != i.Rev {
				f.fail(w, http.StatusPreconditionFailed, `{"message":"VS403351: Test Operation for path /rev failed"}`)
				return
			}
			if strings.HasPrefix(op.Path, "/multilineFieldsFormat/") {
				f.fail(w, http.StatusBadRequest, `{"message":"The type changed without a value"}`)
				return
			}
		}
		f.apply(i, ops)
		i.Rev++
		_ = enc.Encode(f.wire(i))
	case r.Method == http.MethodPost && strings.HasPrefix(rest, "wit/workItems/") && strings.HasSuffix(rest, "/comments"):
		n, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(rest, "wit/workItems/"), "/comments"), 10, 64)
		i := f.items[n]
		text, _ := in["text"].(string)
		i.Comments = append(i.Comments, azComment{Text: azSanitize(text), Format: r.URL.Query().Get("format")})
		i.Rev++
		_ = enc.Encode(map[string]any{"id": len(i.Comments)})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAzure) apply(i *azItem, ops []patchOp) {
	for _, op := range ops {
		if op.Path == "/multilineFieldsFormat/System.Description" {
			i.Format = op.Value.(string)
		}
		if rel, ok := op.Value.(map[string]any); ok && op.Path == "/relations/-" && rel["rel"] == "System.LinkTypes.Hierarchy-Reverse" {
			i.ParentURL = rel["url"].(string)
			i.Parent, _ = strconv.ParseInt(i.ParentURL[strings.LastIndexByte(i.ParentURL, '/')+1:], 10, 64)
		}
		field, ok := strings.CutPrefix(op.Path, "/fields/")
		if !ok {
			continue
		}
		switch field {
		case "System.Title":
			i.Title = op.Value.(string)
		case "System.Description":
			i.Description = azSanitize(op.Value.(string))
		case "System.Tags":
			i.Tags = splitTags(op.Value.(string))
		case "System.State":
			i.State = op.Value.(string)
		default:
			i.Fields[field] = op.Value
		}
	}
}

// azureEnv is an Azure Pipelines job against the fake.
func azureEnv(t *testing.T, srvURL string) {
	t.Helper()
	t.Setenv("TF_BUILD", "True")
	t.Setenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", srvURL+"/acme/")
	t.Setenv("SYSTEM_TEAMPROJECT", "Shop App")
	t.Setenv("SYSTEM_ACCESSTOKEN", "eyJ.pipeline")
	t.Setenv("BUILD_REPOSITORY_ID", "repo-1")
}

func azureItems(t *testing.T, srv *httptest.Server, cfg saga.PublisherConfig) *azureWorkItemPublisher {
	t.Helper()
	azureEnv(t, srv.URL)
	cfg.Kind = "azure-work-item"
	p, err := For(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ap, ok := p.(*azureWorkItemPublisher)
	if !ok {
		t.Fatalf("publisher is %T", p)
	}
	ap.client = srv.Client()
	return ap
}

// publishAzure runs the publisher as a fresh process would, since each pipeline run builds it anew.
func publishAzure(t *testing.T, srv *httptest.Server, cfg saga.PublisherConfig, data report.Data) {
	t.Helper()
	if err := azureItems(t, srv, cfg).PublishRun(context.Background(), data, nil); err != nil {
		t.Fatal(err)
	}
}

// azureCI is an Azure Pipelines run on main, which names no default branch.
func azureCI(controls map[string][]sarif.Result) report.Data {
	d := runOver(controls)
	d.CI = &ci.Context{Branch: "main", RunID: "77", URL: "https://dev.azure.com/acme/Shop%20App/_build/results?buildId=77"}
	return d
}

func failingAzure() report.Data {
	return azureCI(map[string][]sarif.Result{"sca": {codeFinding("api", "c1", "P1", "go.mod")}})
}

func TestAFailingRunOpensOneWorkItemAndAPassingRunClosesIt(t *testing.T) {
	az, srv := newFakeAzure(t)
	publishAzure(t, srv, saga.PublisherConfig{}, failingAzure())
	open := az.open()
	if len(open) != 1 {
		t.Fatalf("open items = %d, want 1", len(open))
	}
	i := open[0]
	if i.Type != "Task" || i.Title == "" || !slices.Equal(i.Tags, []string{"draugr", "draugr:priority:P1"}) ||
		i.Format != "Markdown" || !strings.HasPrefix(azureIn(i.Description), "<!-- draugr:issue v1 project=demo scope=all -->\n") ||
		!strings.Contains(azureIn(i.Description), "### Actions") {
		t.Errorf("item = %+v", i)
	}

	publishAzure(t, srv, saga.PublisherConfig{}, azureCI(map[string][]sarif.Result{"sca": nil}))
	i = az.item(i.ID)
	want := "The gate passes on `main` in [job 77](https://dev.azure.com/acme/Shop%20App/_build/results?buildId=77)."
	if i.State != "Closed" || !slices.Equal(i.said(), []string{want}) || i.Comments[0].Format != "markdown" {
		t.Errorf("item = %s, comments %+v, want Closed with %q in Markdown", i.State, i.Comments, want)
	}
	for _, a := range az.auth {
		if a != "Bearer eyJ.pipeline" {
			t.Fatalf("a request went without the pipeline token as a bearer: %q", a)
		}
	}
}

// Azure stores a description with its comment removed and spaces added, so the body read back is
// never the body written, and an unchanged run must still write nothing.
func TestAnUnchangedRunWritesNothingToAzure(t *testing.T) {
	az, srv := newFakeAzure(t)
	failing := failingAzure()
	publishAzure(t, srv, saga.PublisherConfig{}, failing)
	before := len(az.writes())

	failing.CI = &ci.Context{Branch: "main", RunID: "78", URL: "https://dev.azure.com/acme/Shop%20App/_build/results?buildId=78"}
	publishAzure(t, srv, saga.PublisherConfig{}, failing)
	if got := az.writes()[before:]; len(got) != 0 {
		t.Errorf("an unchanged run wrote %q", got)
	}

	failing.Run.Controls["sca"].Report.Results[0].Location.StartLine = 9
	publishAzure(t, srv, saga.PublisherConfig{}, failing)
	got := az.writes()[before:]
	if len(got) != 1 || got[0] != "PATCH "+azProject+"wit/workitems/1" || !strings.Contains(az.item(1).Description, "go.mod:9") {
		t.Errorf("a changed run wrote %q, want one PATCH", got)
	}
	if ops := az.bodies[len(az.bodies)-1]; ops[0].Op != "test" || ops[0].Path != "/rev" {
		t.Errorf("a rewrite was not guarded by the revision: %+v", ops)
	}
}

// A body survives what Azure does to Markdown, hostile scanner text included, and reads back as
// the body written.
func TestAWorkItemDescriptionRoundTripsThroughTheSanitizer(t *testing.T) {
	hostile := codeFinding("api", "xss", "P1", "a.js")
	hostile.Message = `<b>bold</b> "q" & 'y' a<b <!-- gone -->`
	data := azureCI(map[string][]sarif.Result{"sast": {hostile}})
	body := newIssueBody(data, "all", issueEntry{}, issueParts(data, issueEntry{})[0]).render(markdownFormat{}, azureWorkItemBudget)
	stored := azSanitize(azureOut(body))
	if azureIn(stored) != body {
		t.Errorf("read back\n%s\nwant\n%s", azureIn(stored), body)
	}
	if strings.ContainsAny(stored, "<>") {
		t.Errorf("the sanitizer met a tag in\n%s", stored)
	}
	if bodyChanged(markdownFormat{}, azureIn(stored), body) {
		t.Error("a stored body reads as changed")
	}
	if azureIn(azSanitize(body)) == body {
		t.Error("the fake sanitizer leaves an unescaped body alone, so it proves nothing")
	}
}

// A description at the budget, escaped at the widest, fits the field.
func TestTheBudgetFitsTheFieldOnceEscaped(t *testing.T) {
	if n := len(azSanitize(azureOut(strings.Repeat(`"`, azureWorkItemBudget)))); n > 1_000_000 {
		t.Errorf("a body at the budget stores as %d characters", n)
	}
}

// The format is set when an item is created; setting it again on a rewrite is refused.
func TestTheMarkdownFormatIsSetOnlyOnCreate(t *testing.T) {
	az, srv := newFakeAzure(t)
	publishAzure(t, srv, saga.PublisherConfig{}, failingAzure())
	failing := failingAzure()
	failing.Run.Controls["sca"].Report.Results[0].Location.StartLine = 9
	publishAzure(t, srv, saga.PublisherConfig{}, failing)
	var sets int
	for _, ops := range az.bodies {
		for _, op := range ops {
			if op.Path == "/multilineFieldsFormat/System.Description" {
				sets++
			}
		}
	}
	if i := az.item(1); sets != 1 || i.Format != "Markdown" || !strings.Contains(azureIn(i.Description), "go.mod:9") {
		t.Errorf("format set %d times, item %+v", sets, i)
	}
}

// Two projects in one collection keep separate items, and two scopes in one project keep theirs.
func TestAzureProjectsAndScopesKeepSeparateItems(t *testing.T) {
	az, srv := newFakeAzure(t)
	failing := azureCI(map[string][]sarif.Result{
		"sca":  {codeFinding("api", "c1", "P1", "go.mod")},
		"sast": {codeFinding("web", "r1", "P1", "a.go")},
	})
	split := saga.PublisherConfig{Split: saga.SplitControl}
	publishAzure(t, srv, split, failing)
	publishAzure(t, srv, saga.PublisherConfig{Project: "Shop Ops"}, failing)
	var shop, ops int
	for _, i := range az.open() {
		switch i.Project {
		case "Shop App":
			shop++
		case "Shop Ops":
			ops++
		}
	}
	if shop != 2 || ops != 1 {
		t.Fatalf("items = %d in Shop App, %d in Shop Ops, want 2 and 1", shop, ops)
	}

	publishAzure(t, srv, split, azureCI(map[string][]sarif.Result{"sca": nil, "sast": {codeFinding("web", "r1", "P1", "a.go")}}))
	if n := len(az.open()); n != 2 {
		t.Errorf("open = %d, want the sca item closed and the others open", n)
	}
	if az.item(3).State != "New" {
		t.Error("a run in one project closed an item in another")
	}
}

func TestAWorkItemIsFoundByItsOwnTagAndItsTypesStates(t *testing.T) {
	az, srv := newFakeAzure(t)
	az.statesSeparately = true
	az.add(azItem{Title: "longer tag", Description: "x", Tags: []string{"draugr-other"}})
	az.add(azItem{Type: "User Story", State: "Resolved", Title: "still open", Tags: []string{"Draugr"},
		Description: azureOut("<!-- draugr:issue v1 project=demo scope=all -->\nold")})
	az.add(azItem{Type: "Bug", State: "Resolved", Title: "closed for a bug", Tags: []string{"draugr"},
		Description: azureOut("<!-- draugr:issue v1 project=demo scope=all -->\nold")})
	publishAzure(t, srv, saga.PublisherConfig{}, failingAzure())
	if len(az.items) != 3 {
		t.Fatalf("items = %d, want the resolved story rewritten rather than another created", len(az.items))
	}
	if strings.HasSuffix(az.item(2).Description, "\nold") {
		t.Error("the story was not rewritten")
	}

	publishAzure(t, srv, saga.PublisherConfig{}, azureCI(map[string][]sarif.Result{"sca": nil}))
	if az.item(2).State != "Closed" || az.item(3).State != "Resolved" {
		t.Errorf("states = %s, %s", az.item(2).State, az.item(3).State)
	}
}

func TestADuplicateWorkItemIsClosedWithALink(t *testing.T) {
	az, srv := newFakeAzure(t)
	publishAzure(t, srv, saga.PublisherConfig{}, failingAzure())
	first := az.item(1)
	az.mu.Lock()
	dup := &azItem{ID: 2, Rev: 1, Project: "Shop App", Type: "Task", State: "New", Title: first.Title,
		Description: first.Description, Tags: []string{"draugr"}}
	az.items[2], az.next = dup, 3
	az.mu.Unlock()

	publishAzure(t, srv, saga.PublisherConfig{}, failingAzure())
	want := "Duplicate of [#1](" + srv.URL + "/acme/Shop%20App/_workitems/edit/1)."
	if d := az.item(2); d.State != "Closed" || !slices.Equal(d.said(), []string{want}) {
		t.Errorf("duplicate = %s %q, want %q", d.State, d.said(), want)
	}
}

func TestACreatedWorkItemCarriesTheItemMetadata(t *testing.T) {
	az, srv := newFakeAzure(t)
	publishAzure(t, srv, saga.PublisherConfig{Label: "security", Item: &saga.IssueItem{
		Type: "Bug", Tags: []string{"triage", "Security"}, AssignedTo: "alex@example.com",
		AreaPath: `Shop App\Payments`, IterationPath: `Shop App\Sprint 12`, Priority: new(1),
		Fields: map[string]string{"Microsoft.VSTS.Common.Severity": "2 - High", "Custom.Team": "payments"},
	}}, failingAzure())
	i := az.item(1)
	if i.Type != "Bug" || !slices.Equal(i.Tags, []string{"security", "triage", "draugr:priority:P1"}) {
		t.Errorf("item = %+v", i)
	}
	for field, want := range map[string]any{
		"System.AssignedTo": "alex@example.com", "System.AreaPath": `Shop App\Payments`,
		"System.IterationPath": `Shop App\Sprint 12`, "Microsoft.VSTS.Common.Priority": float64(1),
		"Microsoft.VSTS.Common.Severity": "2 - High", "Custom.Team": "payments",
	} {
		if i.Fields[field] != want {
			t.Errorf("%s = %v, want %v", field, i.Fields[field], want)
		}
	}
	ops := az.bodies[0]
	if ops[len(ops)-2].Path != "/fields/Custom.Team" || ops[len(ops)-1].Path != "/fields/Microsoft.VSTS.Common.Severity" {
		t.Errorf("fields were not written in a stable order: %+v", ops)
	}

	az2, srv2 := newFakeAzure(t)
	err := azureItems(t, srv2, saga.PublisherConfig{Item: &saga.IssueItem{Type: "Epic"}}).PublishRun(context.Background(), failingAzure(), nil)
	if err == nil || !strings.Contains(err.Error(), "create a work item of type Epic in Shop App: 404") || len(az2.items) != 0 {
		t.Errorf("err = %v", err)
	}
}

func TestTagsAzureDroppedAreReported(t *testing.T) {
	az, srv := newFakeAzure(t)
	az.dropTags = true
	err := azureItems(t, srv, saga.PublisherConfig{}).PublishRun(context.Background(), failingAzure(), nil)
	if err == nil || !strings.Contains(err.Error(), "created 1 in Shop App without tag draugr, tag draugr:priority:P1") ||
		!strings.Contains(err.Error(), "Create tag definition") {
		t.Errorf("err = %v", err)
	}
}

func TestAzureTagsAreSyncedInOneGuardedWrite(t *testing.T) {
	az, srv := newFakeAzure(t)
	cfg := saga.PublisherConfig{Item: &saga.IssueItem{Tags: []string{"triage"}}}
	failing := failingAzure()
	publishAzure(t, srv, cfg, failing)

	// Somebody removes triage by hand and adds their own tag, and the finding drops to P2.
	az.item(1).Tags = []string{"draugr", "draugr:priority:P1", "mine"}
	failing.Run.Controls["sca"].Report.Results[0].Priority = "P2"
	failing.Gate = report.GateSettings{FailOnPriority: "P2"}
	before := len(az.writes())
	publishAzure(t, srv, cfg, failing)
	got := az.writes()[before:]
	if len(got) != 2 {
		t.Fatalf("writes = %q, want the description and one tag write", got)
	}
	if tags := az.item(1).Tags; !slices.Equal(tags, []string{"draugr", "mine", "triage", "draugr:priority:P2"}) {
		t.Errorf("tags = %q", tags)
	}
	// The second write is guarded by the revision the first left.
	if ops := az.bodies[len(az.bodies)-1]; ops[0].Value != float64(az.item(1).Rev-1) {
		t.Errorf("tag write tested rev %v, want the one the rewrite left", ops[0].Value)
	}

	before = len(az.writes())
	publishAzure(t, srv, cfg, failing)
	if w := az.writes()[before:]; len(w) != 0 {
		t.Errorf("unchanged tags were written again: %q", w)
	}
}

func TestTheDefaultBranchIsReadFromTheRepository(t *testing.T) {
	az, srv := newFakeAzure(t)
	az.defaultBranch = "refs/heads/trunk"
	publishAzure(t, srv, saga.PublisherConfig{}, failingAzure())
	if len(az.items) != 0 {
		t.Error("a run on main opened an item when the default branch is trunk")
	}
	if !strings.Contains(strings.Join(az.requests, "\n"), "GET "+azProject+"git/repositories/repo-1") {
		t.Errorf("requests = %q", az.requests)
	}

	// branches skips the read, which needs a permission of its own.
	az.requests = nil
	publishAzure(t, srv, saga.PublisherConfig{Branches: []string{"main"}}, failingAzure())
	if len(az.items) != 1 || strings.Contains(strings.Join(az.requests, "\n"), "git/repositories") {
		t.Errorf("items = %d, requests %q", len(az.items), az.requests)
	}

	az.refuse["GET "+azProject+"git/repositories"] = azRefusal{http.StatusForbidden, `{"message":"no"}`}
	err := azureItems(t, srv, saga.PublisherConfig{}).PublishRun(context.Background(), failingAzure(), nil)
	if err == nil || !strings.Contains(err.Error(), "needs Code: Read; naming the branches in branches skips the read") {
		t.Errorf("err = %v", err)
	}
	az.refuse["GET "+azProject+"git/repositories"] = azRefusal{http.StatusInternalServerError, `{"message":"down"}`}
	err = azureItems(t, srv, saga.PublisherConfig{}).PublishRun(context.Background(), failingAzure(), nil)
	if err == nil || !strings.Contains(err.Error(), "read the default branch in Shop App: 500: down") {
		t.Errorf("err = %v", err)
	}
}

func TestAzureRefusalsSayWhatToFix(t *testing.T) {
	for _, c := range []struct {
		name    string
		refuse  string
		refusal azRefusal
		item    *saga.IssueItem
		want    string
	}{
		{"401", "POST " + azProject + "wit/wiql", azRefusal{401, ""}, nil,
			"query work items in Shop App: 401, the token is not valid or has expired"},
		{"403", "POST " + azProject + "wit/wiql", azRefusal{403, `{"message":"denied"}`}, nil,
			"403, the identity needs View and Edit work items in this node on the area path"},
		{"404", "GET " + azProject + "wit/workitemtypes", azRefusal{404, `{"message":"gone"}`}, nil,
			"read work item types in Shop App: 404, the project, type or item does not exist"},
		{"assignee", "POST " + azProject + "wit/workitems", azRefusal{400,
			`{"message":"The identity value 'x' for field 'Assigned To' is an unknown identity.","customProperties":{"ReferenceName":"System.AssignedTo"}}`},
			&saga.IssueItem{AssignedTo: "x"}, "create a work item of type Task in Shop App: 400, item.assignedTo: The identity value"},
		{"custom field", "POST " + azProject + "wit/workitems", azRefusal{400,
			`{"message":"TF51535: Cannot find field Custom.Team.","customProperties":{"ReferenceName":"Custom.Team"}}`},
			nil, "400, item.fields Custom.Team: TF51535"},
		{"plain", "POST " + azProject + "wit/workitems", azRefusal{500, "oops"}, nil, "500: oops"},
	} {
		t.Run(c.name, func(t *testing.T) {
			az, srv := newFakeAzure(t)
			az.refuse[c.refuse] = c.refusal
			err := azureItems(t, srv, saga.PublisherConfig{Item: c.item}).PublishRun(context.Background(), failingAzure(), nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestAWorkItemChangedDuringTheRunIsReported(t *testing.T) {
	az, srv := newFakeAzure(t)
	failing := failingAzure()
	publishAzure(t, srv, saga.PublisherConfig{}, failing)
	p := azureItems(t, srv, saga.PublisherConfig{})
	if _, err := p.open(context.Background()); err != nil {
		t.Fatal(err)
	}
	az.item(1).Rev++ // somebody edits it
	err := p.rewrite(context.Background(), 1, "new")
	if err == nil || !strings.Contains(err.Error(), "412, somebody changed the item while the run was writing it") {
		t.Errorf("err = %v", err)
	}
}

func TestAWorkItemTypeWithNoCompletedStateIsNamed(t *testing.T) {
	az, srv := newFakeAzure(t)
	az.states["Odd"] = [][2]string{{"New", "Proposed"}}
	az.add(azItem{Type: "Odd", Tags: []string{"draugr"}, Description: azureOut("<!-- draugr:issue v1 project=demo scope=all -->\nx")})
	err := azureItems(t, srv, saga.PublisherConfig{}).PublishRun(context.Background(), azureCI(map[string][]sarif.Result{"sca": nil}), nil)
	if err == nil || !strings.Contains(err.Error(), "the Odd type in Shop App has no state in the Completed category") {
		t.Errorf("err = %v", err)
	}
}

func TestAnUnreadableAzureAnswerIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>"))
	}))
	t.Cleanup(srv.Close)
	p := azureItems(t, srv, saga.PublisherConfig{Branches: []string{"main"}})
	if err := p.PublishRun(context.Background(), failingAzure(), nil); err == nil || !strings.Contains(err.Error(), "read work item types in Shop App") {
		t.Errorf("err = %v", err)
	}
	srv.Close()
	if err := p.PublishRun(context.Background(), failingAzure(), nil); err == nil || !strings.Contains(err.Error(), "read work item types in Shop App") {
		t.Errorf("unreachable: err = %v", err)
	}
}

func TestTheAzureWorkItemPublisherNeedsAProjectAndAToken(t *testing.T) {
	for _, k := range []string{"TF_BUILD", "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "SYSTEM_TEAMPROJECT", "SYSTEM_ACCESSTOKEN"} {
		t.Setenv(k, "")
	}
	p, err := For(saga.PublisherConfig{Kind: "azure-work-item"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(skipPublisher); !ok {
		t.Errorf("outside Azure Pipelines = %T, want a skip", p)
	}

	t.Setenv("TF_BUILD", "True")
	_, err = For(saga.PublisherConfig{Kind: "azure-work-item"})
	if err == nil || !strings.Contains(err.Error(), "org (or $SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)") ||
		!strings.Contains(err.Error(), "project (or $SYSTEM_TEAMPROJECT)") ||
		!strings.Contains(err.Error(), "env: {SYSTEM_ACCESSTOKEN: $(System.AccessToken)}") {
		t.Errorf("err = %v", err)
	}

	t.Setenv("BOARDS_PAT", "pat")
	p, err = For(saga.PublisherConfig{Kind: "azure-work-item", Org: "https://dev.azure.com/acme", Project: "Shop", TokenEnv: "BOARDS_PAT"})
	if err != nil || p.Kind() != "azure-work-item" {
		t.Fatalf("org, project and tokenEnv: %v, %v", p, err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	azureAuthorize(req, "pat")
	if req.Header.Get("Authorization") != "Basic OnBhdA==" {
		t.Errorf("a personal access token went as %q", req.Header.Get("Authorization"))
	}
	if err := p.Publish(context.Background(), nil); err == nil {
		t.Error("Publish without the run did nothing")
	}
	if got := p.(*azureWorkItemPublisher).ref(12); got != "[#12](https://dev.azure.com/acme/Shop/_workitems/edit/12)" {
		t.Errorf("ref = %s", got)
	}
}
