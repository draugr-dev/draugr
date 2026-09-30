package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// azureWorkItemBudget is the longest description written to a work item. Azure DevOps holds
// 1,000,000 characters in a long-text field, and the margin covers what its sanitizer adds.
const azureWorkItemBudget = 900_000

// azureIDBatch is the most work items one `GET _apis/wit/workitems?ids=` returns.
const azureIDBatch = 200

// State categories a process maps its state names to. Categories are fixed; names are not.
const (
	azureCompleted = "Completed"
	azureRemoved   = "Removed"
)

// azureWorkItemPublisher keeps one Azure Boards work item open for each failing part of the gate
// and closes it when that part passes. The collection and project come from the pipeline, as for
// azure-pr-comment.
//
// An item is found by tag and identified by the marker in its description. Azure DevOps removes
// HTML comments from a description, so the marker travels in a data attribute and is read back
// into the form every other kind stores.
type azureWorkItemPublisher struct {
	cfg              saga.PublisherConfig
	baseURL, project string
	token            string
	label            string
	client           *http.Client
	// seen is what open learned about each item, which the writes after it need.
	seen map[int64]azureSeen
	// states maps a work item type to its states' categories, filled as types are met.
	states map[string]map[string]string
}

// azureSeen is an item's revision, which guards a write against an edit made since it was read,
// and its type, which names the state it closes to.
type azureSeen struct {
	rev      int
	itemType string
}

func newAzureWorkItemPublisher(cfg saga.PublisherConfig) (Publisher, error) {
	tokenEnv := firstNonEmpty(cfg.TokenEnv, "SYSTEM_ACCESSTOKEN")
	collection := firstNonEmpty(cfg.Org, os.Getenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"))
	p := &azureWorkItemPublisher{
		cfg:     cfg,
		project: firstNonEmpty(cfg.Project, os.Getenv("SYSTEM_TEAMPROJECT")),
		token:   os.Getenv(tokenEnv),
		label:   firstNonEmpty(cfg.Label, defaultIssueLabel),
		client:  newIssueClient(http.DefaultClient),
		seen:    map[int64]azureSeen{},
		states:  map[string]map[string]string{},
	}
	if os.Getenv("TF_BUILD") != "True" && cfg.Org == "" && p.token == "" {
		return skipPublisher{kind: "azure-work-item", reason: "not an Azure Pipelines environment"}, nil
	}
	var missing []string
	if collection == "" {
		missing = append(missing, "org (or $SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)")
	}
	if p.project == "" {
		missing = append(missing, "project (or $SYSTEM_TEAMPROJECT)")
	}
	if p.token == "" {
		missing = append(missing, "$"+tokenEnv+", mapped into the step with `env: {SYSTEM_ACCESSTOKEN: $(System.AccessToken)}`, "+
			"or a personal access token with Work Items: Read & Write")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("azure-work-item publisher missing: %s", strings.Join(missing, "; "))
	}
	p.baseURL = strings.TrimSuffix(collection, "/") + "/" + url.PathEscape(p.project) + "/_apis/"
	return p, nil
}

func (*azureWorkItemPublisher) Kind() string { return "azure-work-item" }

// Publish is never the path a run takes, since Run calls PublishRun. Without the run there is no
// gate to follow, so it refuses rather than doing nothing.
func (*azureWorkItemPublisher) Publish(context.Context, []report.Artifact) error {
	return errors.New("azure-work-item publisher follows the gate, and needs the run: call PublishRun")
}

// PublishRun opens, rewrites and closes the entry's work items to match the run. Azure Pipelines
// names no default branch in the environment, so unless `branches` is set it is read from the
// repository before the run is judged.
func (p *azureWorkItemPublisher) PublishRun(ctx context.Context, data report.Data, _ []report.Artifact) error {
	if c := data.CI; c != nil && len(p.cfg.Branches) == 0 && c.DefaultBranch == "" && !c.PullRequest && c.Branch != "" {
		if id := os.Getenv("BUILD_REPOSITORY_ID"); id != "" {
			branch, err := p.defaultBranch(ctx, id)
			if err != nil {
				return err
			}
			withDefault := *c
			withDefault.DefaultBranch = branch
			data.CI = &withDefault
		}
	}
	return trackIssues(ctx, p, data, p.cfg)
}

func (*azureWorkItemPublisher) kind() string        { return "azure-work-item" }
func (*azureWorkItemPublisher) format() issueFormat { return htmlFormat{} }
func (*azureWorkItemPublisher) budget() int         { return azureWorkItemBudget }

// ref links another work item. A comment written through the API links no bare `#12`.
func (p *azureWorkItemPublisher) ref(n int64) string {
	id := strconv.FormatInt(n, 10)
	return `<a href="` + html.EscapeString(strings.TrimSuffix(p.baseURL, "_apis/")+"_workitems/edit/"+id) + `">#` + id + "</a>"
}

// defaultBranch reads the repository's default branch, which Azure reports as a full ref.
func (p *azureWorkItemPublisher) defaultBranch(ctx context.Context, repoID string) (string, error) {
	var repo struct {
		DefaultBranch string `json:"defaultBranch"`
	}
	target := p.baseURL + "git/repositories/" + url.PathEscape(repoID) + "?api-version=7.1"
	if err := p.do(ctx, "read the default branch", http.MethodGet, target, "", nil, &repo); err != nil {
		var se *azureStatusError
		if errors.As(err, &se) && (se.status == http.StatusUnauthorized || se.status == http.StatusForbidden) {
			return "", fmt.Errorf("%w. Reading it needs Code: Read; naming the branches in branches skips the read", err)
		}
		return "", err
	}
	return strings.TrimPrefix(repo.DefaultBranch, "refs/heads/"), nil
}

type azureWorkItem struct {
	ID     int64 `json:"id"`
	Rev    int   `json:"rev"`
	Fields struct {
		Type        string          `json:"System.WorkItemType"`
		State       string          `json:"System.State"`
		Description string          `json:"System.Description"`
		Tags        string          `json:"System.Tags"`
		AssignedTo  json.RawMessage `json:"System.AssignedTo"`
	} `json:"fields"`
}

// open lists the open work items carrying the tracking tag, oldest first.
//
// The query leaves out the states that close an item in every type, which keeps closed items out
// of the batch reads that follow; each item's own type then decides whether it is open.
func (p *azureWorkItemPublisher) open(ctx context.Context) ([]trackedItem, error) {
	closed, err := p.closedNames(ctx)
	if err != nil {
		return nil, err
	}
	q := "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS " + wiqlString(p.label)
	if len(closed) > 0 {
		quoted := make([]string, len(closed))
		for i, s := range closed {
			quoted[i] = wiqlString(s)
		}
		q += " AND [System.State] NOT IN (" + strings.Join(quoted, ", ") + ")"
	}
	q += " ORDER BY [System.Id]"
	var found struct {
		WorkItems []struct {
			ID int64 `json:"id"`
		} `json:"workItems"`
	}
	if err := p.do(ctx, "query work items", http.MethodPost, p.baseURL+"wit/wiql?api-version=7.1", "application/json",
		map[string]string{"query": q}, &found); err != nil {
		return nil, err
	}

	var out []trackedItem
	for start := 0; start < len(found.WorkItems); start += azureIDBatch {
		batch := found.WorkItems[start:min(start+azureIDBatch, len(found.WorkItems))]
		ids := make([]string, len(batch))
		for i, w := range batch {
			ids[i] = strconv.FormatInt(w.ID, 10)
		}
		var got struct {
			Value []azureWorkItem `json:"value"`
		}
		target := p.baseURL + "wit/workitems?ids=" + strings.Join(ids, ",") +
			"&fields=System.WorkItemType,System.State,System.Description,System.Tags&api-version=7.1"
		if err := p.do(ctx, "read work items", http.MethodGet, target, "", nil, &got); err != nil {
			return nil, err
		}
		for _, w := range got.Value {
			tags := splitTags(w.Fields.Tags)
			if !containsFold(tags, p.label) {
				continue // CONTAINS matched a longer tag
			}
			category, err := p.category(ctx, w.Fields.Type, w.Fields.State)
			if err != nil {
				return nil, err
			}
			if category == azureCompleted || category == azureRemoved {
				continue
			}
			p.seen[w.ID] = azureSeen{rev: w.Rev, itemType: w.Fields.Type}
			out = append(out, trackedItem{Number: w.ID, Body: azureIn(w.Fields.Description), Labels: tags})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out, nil
}

// create opens a work item with the tracking tag, the configured metadata and the fact tags, then
// checks that Azure kept every tag. A tag is new to the organization the first time it is used,
// and creating one takes a permission of its own.
func (p *azureWorkItemPublisher) create(ctx context.Context, title, body string, facts []string) error {
	item := p.item()
	itemType := item.Type
	if itemType == "" {
		t, err := p.defaultType(ctx)
		if err != nil {
			return err
		}
		itemType = t
	}
	var tags []string
	for _, t := range append(append([]string{p.label}, item.Tags...), facts...) {
		if !containsFold(tags, t) {
			tags = append(tags, t)
		}
	}
	ops := []patchOp{
		{Op: "add", Path: "/fields/System.Title", Value: title},
		{Op: "add", Path: "/fields/System.Description", Value: azureOut(body)},
		{Op: "add", Path: "/fields/System.Tags", Value: strings.Join(tags, "; ")},
	}
	for _, f := range []struct{ field, value string }{
		{"System.AssignedTo", item.AssignedTo},
		{"System.AreaPath", item.AreaPath},
		{"System.IterationPath", item.IterationPath},
	} {
		if f.value != "" {
			ops = append(ops, patchOp{Op: "add", Path: "/fields/" + f.field, Value: f.value})
		}
	}
	if item.Priority != nil {
		ops = append(ops, patchOp{Op: "add", Path: "/fields/Microsoft.VSTS.Common.Priority", Value: *item.Priority})
	}
	names := make([]string, 0, len(item.Fields))
	for name := range item.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ops = append(ops, patchOp{Op: "add", Path: "/fields/" + name, Value: item.Fields[name]})
	}

	var got azureWorkItem
	target := p.baseURL + "wit/workitems/" + url.PathEscape("$"+itemType) + "?api-version=7.1"
	if err := p.do(ctx, "create a work item of type "+itemType, http.MethodPost, target, "application/json-patch+json", ops, &got); err != nil {
		return err
	}
	var dropped []string
	kept := splitTags(got.Fields.Tags)
	for _, t := range tags {
		if !containsFold(kept, t) {
			dropped = append(dropped, "tag "+t)
		}
	}
	if item.AssignedTo != "" && (len(got.Fields.AssignedTo) == 0 || string(got.Fields.AssignedTo) == "null") {
		dropped = append(dropped, "assignedTo "+item.AssignedTo)
	}
	if len(dropped) > 0 {
		return fmt.Errorf("azure-work-item publisher: created %d in %s without %s. A tag new to the organization needs "+
			"Create tag definition", got.ID, p.project, strings.Join(dropped, ", "))
	}
	return nil
}

// rewrite replaces the description, unless the item changed since it was read.
func (p *azureWorkItemPublisher) rewrite(ctx context.Context, n int64, body string) error {
	return p.patch(ctx, "update", n, patchOp{Op: "add", Path: "/fields/System.Description", Value: azureOut(body)})
}

// syncLabels writes the item's tags when a configured tag is missing or a fact tag is stale, in
// one write, unless the item changed since it was read. Azure keeps tags as one field, so the
// write carries every tag the item keeps.
func (p *azureWorkItemPublisher) syncLabels(ctx context.Context, item trackedItem, facts []string) error {
	var tags []string
	changed := false
	for _, t := range item.Labels {
		if saga.IsFactLabel(t) && !containsFold(facts, t) {
			changed = true
			continue
		}
		tags = append(tags, t)
	}
	for _, t := range append(append([]string(nil), p.item().Tags...), facts...) {
		if !containsFold(tags, t) {
			tags = append(tags, t)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return p.patch(ctx, "tag", item.Number, patchOp{Op: "add", Path: "/fields/System.Tags", Value: strings.Join(tags, "; ")})
}

// comment posts an HTML comment. The markdown `format` parameter exists only on 7.2-preview.
func (p *azureWorkItemPublisher) comment(ctx context.Context, n int64, text string) error {
	target := p.baseURL + "wit/workItems/" + strconv.FormatInt(n, 10) + "/comments?api-version=7.1-preview.4"
	return p.do(ctx, "comment on "+strconv.FormatInt(n, 10), http.MethodPost, target, "application/json",
		map[string]string{"text": text}, nil)
}

// close moves the item to its type's Completed state. The comment posted before it says why, and
// has already changed the item's revision, so the write is not guarded.
func (p *azureWorkItemPublisher) close(ctx context.Context, n int64, _ closeReason) error {
	itemType := p.seen[n].itemType
	var completed string
	for name, category := range p.states[itemType] {
		if category == azureCompleted {
			completed = name
		}
	}
	if completed == "" {
		return fmt.Errorf("azure-work-item publisher: the %s type in %s has no state in the Completed category to close %d to",
			itemType, p.project, n)
	}
	target := p.baseURL + "wit/workitems/" + strconv.FormatInt(n, 10) + "?api-version=7.1"
	return p.do(ctx, "close "+strconv.FormatInt(n, 10), http.MethodPatch, target, "application/json-patch+json",
		[]patchOp{{Op: "add", Path: "/fields/System.State", Value: completed}}, nil)
}

// patchOp is one operation of a JSON Patch document.
type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// patch applies one change guarded by the revision open read, and records the revision it leaves.
func (p *azureWorkItemPublisher) patch(ctx context.Context, what string, n int64, op patchOp) error {
	seen := p.seen[n]
	var got azureWorkItem
	target := p.baseURL + "wit/workitems/" + strconv.FormatInt(n, 10) + "?api-version=7.1"
	if err := p.do(ctx, what+" "+strconv.FormatInt(n, 10), http.MethodPatch, target, "application/json-patch+json",
		[]patchOp{{Op: "test", Path: "/rev", Value: seen.rev}, op}, &got); err != nil {
		return err
	}
	seen.rev = got.Rev
	p.seen[n] = seen
	return nil
}

// defaultType is the default type of the Task category, Task in every process that ships with
// Azure DevOps. A process can rename or disable a type, and the category follows it.
func (p *azureWorkItemPublisher) defaultType(ctx context.Context) (string, error) {
	var cat struct {
		DefaultWorkItemType struct {
			Name string `json:"name"`
		} `json:"defaultWorkItemType"`
	}
	if err := p.do(ctx, "read the Task category", http.MethodGet,
		p.baseURL+"wit/workitemtypecategories/Microsoft.TaskCategory?api-version=7.1", "", nil, &cat); err != nil {
		return "", err
	}
	if cat.DefaultWorkItemType.Name == "" {
		return "", fmt.Errorf("azure-work-item publisher: the Task category in %s has no default type; set item.type", p.project)
	}
	return cat.DefaultWorkItemType.Name, nil
}

// closedNames lists the state names that are Completed or Removed in every type that has them,
// the ones an open query can leave out without losing an open item of another type.
func (p *azureWorkItemPublisher) closedNames(ctx context.Context) ([]string, error) {
	var types struct {
		Value []struct {
			Name   string `json:"name"`
			States []struct {
				Name     string `json:"name"`
				Category string `json:"category"`
			} `json:"states"`
		} `json:"value"`
	}
	if err := p.do(ctx, "read work item types", http.MethodGet, p.baseURL+"wit/workitemtypes?api-version=7.1", "", nil, &types); err != nil {
		return nil, err
	}
	closed := map[string]bool{}
	for _, t := range types.Value {
		if len(t.States) == 0 {
			continue
		}
		states := map[string]string{}
		for _, s := range t.States {
			states[s.Name] = s.Category
			isClosed := s.Category == azureCompleted || s.Category == azureRemoved
			if was, ok := closed[s.Name]; !ok || was {
				closed[s.Name] = isClosed
			}
		}
		p.states[t.Name] = states
	}
	var out []string
	for name, isClosed := range closed {
		if isClosed {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// category is the category of a state in a type, reading the type's states when the type list
// carried none.
func (p *azureWorkItemPublisher) category(ctx context.Context, itemType, state string) (string, error) {
	if _, ok := p.states[itemType]; !ok {
		var got struct {
			Value []struct {
				Name     string `json:"name"`
				Category string `json:"category"`
			} `json:"value"`
		}
		target := p.baseURL + "wit/workitemtypes/" + url.PathEscape(itemType) + "/states?api-version=7.1"
		if err := p.do(ctx, "read the states of "+itemType, http.MethodGet, target, "", nil, &got); err != nil {
			return "", err
		}
		states := map[string]string{}
		for _, s := range got.Value {
			states[s.Name] = s.Category
		}
		p.states[itemType] = states
	}
	return p.states[itemType][state], nil
}

func (p *azureWorkItemPublisher) item() saga.IssueItem {
	if p.cfg.Item == nil {
		return saga.IssueItem{}
	}
	return *p.cfg.Item
}

// wiqlString quotes a value for a WIQL query, doubling any single quote in it.
func wiqlString(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// splitTags reads Azure's tag field, which separates tags with a semicolon and a space.
func splitTags(field string) []string {
	var out []string
	for _, t := range strings.Split(field, ";") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// azureMarker finds the element carrying the marker in a description as Azure stores it.
var azureMarker = regexp.MustCompile(`<div\s[^>]*?data-draugr-issue="([^"]*)"[^>]*>`)

// azureOut moves a body's marker into a data attribute on an element wrapping the body, since
// Azure removes HTML comments from a description and keeps data attributes.
func azureOut(body string) string {
	marker := markerLine(body)
	if marker == "" {
		return body
	}
	fields := strings.TrimSuffix(strings.TrimPrefix(marker, "<!-- draugr:issue "), " -->")
	rest := strings.TrimLeft(strings.Replace(body, marker, "", 1), "\n")
	return `<div data-draugr-issue="` + html.EscapeString(fields) + `">` + rest + "</div>"
}

// azureIn reverses azureOut on a description read back, so the marker is found and the body
// compared as every other kind stores them.
func azureIn(desc string) string {
	m := azureMarker.FindStringSubmatchIndex(desc)
	if m == nil {
		return desc
	}
	fields := html.UnescapeString(desc[m[2]:m[3]])
	rest := desc[:m[0]] + desc[m[1]:]
	if i := strings.LastIndex(rest, "</div>"); i >= 0 {
		rest = rest[:i] + rest[i+len("</div>"):]
	}
	return "<!-- draugr:issue " + fields + " -->\n" + strings.TrimSpace(rest)
}

// azureStatusError is an answer Azure DevOps gave that was not a success, worded for the reader
// who has to fix it.
type azureStatusError struct {
	status        int
	what, project string
	message       string
	field         string
}

func (e *azureStatusError) Error() string {
	prefix := fmt.Sprintf("azure-work-item publisher: %s in %s", e.what, e.project)
	switch e.status {
	case http.StatusUnauthorized:
		return prefix + ": 401, the token is not valid or has expired"
	case http.StatusForbidden:
		return prefix + ": 403, the identity needs View and Edit work items in this node on the area path, " +
			"and Create tag definition for a new tag: " + e.message
	case http.StatusNotFound:
		return prefix + ": 404, the project, type or item does not exist, or the token cannot see it: " + e.message
	case http.StatusPreconditionFailed:
		return prefix + ": 412, somebody changed the item while the run was writing it; the next run writes it again"
	}
	if key := saga.AzureFieldKeys[e.field]; key != "" {
		return fmt.Sprintf("%s: %d, %s: %s", prefix, e.status, key, e.message)
	}
	if e.field != "" && strings.Contains(e.field, ".") {
		return fmt.Sprintf("%s: %d, item.fields %s: %s", prefix, e.status, e.field, e.message)
	}
	return fmt.Sprintf("%s: %d: %s", prefix, e.status, e.message)
}

// do sends one request, decoding a success into out when out is not nil.
func (p *azureWorkItemPublisher) do(ctx context.Context, what, method, target, contentType string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body) //nolint:gosec // collection URI from env
	if err != nil {
		return err
	}
	azureAuthorize(req, p.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := p.client.Do(req) // #nosec G704 -- the collection and repository come from the pipeline's own environment
	if err != nil {
		return fmt.Errorf("azure-work-item publisher: %s in %s: %w", what, p.project, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var detail struct {
			Message          string `json:"message"`
			CustomProperties struct {
				ReferenceName string `json:"ReferenceName"`
			} `json:"customProperties"`
		}
		msg := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &detail) == nil && detail.Message != "" {
			msg = detail.Message
		}
		return &azureStatusError{status: resp.StatusCode, what: what, project: p.project, message: msg,
			field: detail.CustomProperties.ReferenceName}
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("azure-work-item publisher: %s in %s: %w", what, p.project, err)
		}
	}
	return nil
}
