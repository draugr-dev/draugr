package publish

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// memItem is one item as the in-memory tracker holds it.
type memItem struct {
	trackedItem
	Title    string
	Parent   int64
	Open     bool
	Reason   closeReason
	Comments []string
}

// memTracker is a forge held in memory, for the decisions trackIssues makes rather than the
// requests a forge is sent.
type memTracker struct {
	items  []*memItem // an item's number is its index plus one
	writes []string
	// left is how many writes the run's budget still covers; negative is unlimited.
	left int
	// fail makes the write whose description starts with it return an error.
	fail string
}

func newMemTracker() *memTracker { return &memTracker{left: -1} }

func (m *memTracker) write(what string) error {
	if m.fail != "" && strings.HasPrefix(what, m.fail) {
		return errors.New("refused: " + what)
	}
	m.writes = append(m.writes, what)
	if m.left > 0 {
		m.left--
	}
	return nil
}

func (m *memTracker) item(n int64) *memItem { return m.items[n-1] }

func (m *memTracker) kind() string        { return "github-issue" }
func (m *memTracker) format() issueFormat { return markdownFormat{} }
func (m *memTracker) budget() int         { return 65_536 }
func (m *memTracker) childWrites() int    { return 2 }
func (m *memTracker) ref(n int64) string  { return fmt.Sprintf("#%d", n) }
func (m *memTracker) affords(writes int) bool {
	return m.left < 0 || writes <= m.left
}

func (m *memTracker) open(context.Context) ([]trackedItem, error) {
	var out []trackedItem
	for _, it := range m.items {
		if it.Open {
			out = append(out, it.trackedItem)
		}
	}
	return out, nil
}

func (m *memTracker) create(_ context.Context, title, body string, facts []string, parent *trackedItem) (trackedItem, error) {
	if err := m.write("create " + title); err != nil {
		return trackedItem{}, err
	}
	n := int64(len(m.items) + 1)
	it := &memItem{trackedItem: trackedItem{Number: n, ID: 1000 + n, Body: body, Labels: facts}, Title: title, Open: true}
	if parent != nil {
		if parent.ID == 0 {
			return trackedItem{}, errors.New("a parent with no id")
		}
		it.Parent = parent.Number
		if m.left > 0 {
			m.left--
		}
	}
	m.items = append(m.items, it)
	return it.trackedItem, nil
}

func (m *memTracker) rewrite(_ context.Context, n int64, body string) error {
	if err := m.write(fmt.Sprintf("rewrite #%d", n)); err != nil {
		return err
	}
	m.item(n).Body = body
	return nil
}

func (m *memTracker) retitle(_ context.Context, n int64, title string) error {
	if err := m.write(fmt.Sprintf("retitle #%d %s", n, title)); err != nil {
		return err
	}
	m.item(n).Title = title
	return nil
}

func (m *memTracker) syncLabels(_ context.Context, it trackedItem, facts []string) error {
	cur := m.item(it.Number)
	if slices.Equal(cur.Labels, facts) {
		return nil
	}
	if err := m.write(fmt.Sprintf("labels #%d", it.Number)); err != nil {
		return err
	}
	cur.Labels = facts
	return nil
}

func (m *memTracker) comment(_ context.Context, n int64, text string) error {
	if err := m.write(fmt.Sprintf("comment #%d", n)); err != nil {
		return err
	}
	m.item(n).Comments = append(m.item(n).Comments, text)
	return nil
}

func (m *memTracker) close(_ context.Context, n int64, reason closeReason) error {
	if err := m.write(fmt.Sprintf("close #%d", n)); err != nil {
		return err
	}
	m.item(n).Open, m.item(n).Reason = false, reason
	return nil
}

// copyOf adds an open item with the body and parent of item n, and returns its number.
func (m *memTracker) copyOf(n int64) int64 {
	c := *m.item(n)
	c.Number = int64(len(m.items) + 1)
	c.Comments = nil
	m.items = append(m.items, &c)
	return c.Number
}

// openOnes is the open items, parents and children alike.
func (m *memTracker) openOnes() []*memItem {
	var out []*memItem
	for _, it := range m.items {
		if it.Open {
			out = append(out, it)
		}
	}
	return out
}

// kidsOf is the open children of a parent, in creation order.
func (m *memTracker) kidsOf(parent int64) []*memItem {
	var out []*memItem
	for _, it := range m.openOnes() {
		if it.Parent == parent {
			out = append(out, it)
		}
	}
	return out
}

// parents is the open items with no parent.
func (m *memTracker) parents() []*memItem {
	var out []*memItem
	for _, it := range m.openOnes() {
		if it.Parent == 0 {
			out = append(out, it)
		}
	}
	return out
}

func (m *memTracker) titles(items []*memItem) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Title
	}
	return out
}

func track(t *testing.T, m *memTracker, data report.Data, cfg saga.PublisherConfig) {
	t.Helper()
	cfg.Kind = "github-issue"
	if err := trackIssues(context.Background(), m, data, cfg); err != nil {
		t.Fatal(err)
	}
}

// threeRules is a run whose sast control fails with a rule action at each of P1, P2 and P3.
func threeRules() report.Data {
	return onMain(map[string][]sarif.Result{"sast": {
		codeFinding("api", "r1", "P1", "a.go"),
		codeFinding("api", "r2", "P2", "b.go"),
		codeFinding("api", "r3", "P3", "c.go"),
	}})
}

var perAction = saga.PublisherConfig{Children: saga.ChildrenActions}

func TestEachActionGetsAChildAndTheParentListsNone(t *testing.T) {
	m := newMemTracker()
	track(t, m, threeRules(), perAction)

	parents := m.parents()
	if len(parents) != 1 {
		t.Fatalf("parents = %d, want 1", len(parents))
	}
	p := parents[0]
	kids := m.kidsOf(p.Number)
	want := []string{"P1 · Fix r1", "P2 · Fix r2", "P3 · Fix r3"}
	if got := m.titles(kids); !slices.Equal(got, want) {
		t.Fatalf("children = %q, want %q", got, want)
	}
	if strings.Contains(p.Body, "### Actions") {
		t.Errorf("a parent whose actions all have a child lists them\n%s", p.Body)
	}
	k := kids[0]
	parentMarker, field := splitMarker(markerLine(k.Body))
	if parentMarker != markerLine(p.Body) || !strings.HasPrefix(field, "action=") {
		t.Errorf("child marker %q under parent %q", markerLine(k.Body), markerLine(p.Body))
	}
	for _, line := range []string{
		"<!-- draugr:priority P1 -->",
		"**P1** · `sast` · 1 finding · gate P1",
		"### Findings",
		"or when a run no longer reports this action.",
	} {
		if !strings.Contains(k.Body, line) {
			t.Errorf("child lacks %q\n%s", line, k.Body)
		}
	}
}

func TestAnUnchangedFamilySendsNoWrite(t *testing.T) {
	m := newMemTracker()
	track(t, m, threeRules(), perAction)
	before := len(m.writes)
	track(t, m, threeRules(), perAction)
	if got := m.writes[before:]; len(got) != 0 {
		t.Errorf("an unchanged run wrote %q", got)
	}
}

func TestAnActionTheRunNoLongerReportsClosesItsChild(t *testing.T) {
	m := newMemTracker()
	track(t, m, threeRules(), perAction)
	gone := m.kidsOf(1)[1]

	track(t, m, onMain(map[string][]sarif.Result{"sast": {
		codeFinding("api", "r1", "P1", "a.go"),
		codeFinding("api", "r3", "P3", "c.go"),
	}}), perAction)
	if gone.Open || gone.Reason != closedPassing {
		t.Errorf("child of the fixed action: open %v, reason %v", gone.Open, gone.Reason)
	}
	if want := []string{"The run no longer reports this action."}; !slices.Equal(gone.Comments, want) {
		t.Errorf("comments = %q, want %q", gone.Comments, want)
	}
	if n := len(m.kidsOf(1)); n != 2 {
		t.Errorf("open children = %d, want 2", n)
	}
}

func TestAPassingRunClosesTheChildrenThenTheParent(t *testing.T) {
	m := newMemTracker()
	track(t, m, threeRules(), perAction)
	m.writes = nil

	track(t, m, onMain(map[string][]sarif.Result{"sast": nil}), perAction)
	if open := m.openOnes(); len(open) != 0 {
		t.Fatalf("open items = %d, want 0", len(open))
	}
	want := []string{"comment #2", "close #2", "comment #3", "close #3", "comment #4", "close #4", "comment #1", "close #1"}
	if !slices.Equal(m.writes, want) {
		t.Errorf("writes = %q, want %q", m.writes, want)
	}
}

func TestMaxChildrenLeavesTheRestInTheParent(t *testing.T) {
	m := newMemTracker()
	cfg := perAction
	cfg.MaxChildren = new(2)
	track(t, m, threeRules(), cfg)

	p := m.parents()[0]
	if got := m.titles(m.kidsOf(p.Number)); !slices.Equal(got, []string{"P1 · Fix r1", "P2 · Fix r2"}) {
		t.Fatalf("children = %q", got)
	}
	lead := "2 of 3 actions have an item. The other is listed below and gets an item as open items close, since `maxChildren` is 2."
	if !strings.Contains(p.Body, lead) || !strings.Contains(p.Body, "Fix r3") || strings.Contains(p.Body, "Fix r1") {
		t.Errorf("parent body\n%s", p.Body)
	}

	// The first child closes by hand; the next run gives the waiting action its child.
	m.item(2).Open = false
	track(t, m, threeRules(), cfg)
	if got := m.titles(m.kidsOf(p.Number)); !slices.Equal(got, []string{"P2 · Fix r2", "P1 · Fix r1"}) {
		t.Errorf("children after one closed by hand = %q", got)
	}
	if strings.Contains(p.Body, "Fix r1") || !strings.Contains(p.Body, "Fix r3") {
		t.Errorf("parent body after the recreate\n%s", p.Body)
	}
}

func TestABudgetThatRunsOutLeavesTheRestForTheNextRun(t *testing.T) {
	m := newMemTracker()
	// The parent, one child, and the write held back for no further parent.
	m.left = 1 + 2 + 1
	track(t, m, threeRules(), perAction)

	p := m.parents()[0]
	if n := len(m.kidsOf(p.Number)); n != 1 {
		t.Fatalf("children = %d, want 1", n)
	}
	lead := "1 of 3 actions has an item. The other 2 are listed below and get an item on the next run."
	if !strings.Contains(p.Body, lead) {
		t.Errorf("parent body lacks %q\n%s", lead, p.Body)
	}

	m.left = -1
	track(t, m, threeRules(), perAction)
	if n := len(m.kidsOf(p.Number)); n != 3 {
		t.Errorf("children after the next run = %d, want 3", n)
	}
	if strings.Contains(p.Body, "### Actions") {
		t.Errorf("the parent still lists actions\n%s", p.Body)
	}
}

func TestAChangedPriorityRetitlesAChildAndKeepsARenameOtherwise(t *testing.T) {
	m := newMemTracker()
	track(t, m, threeRules(), perAction)
	m.item(3).Title = "renamed by somebody"
	m.item(4).Title = "also renamed"
	m.writes = nil

	track(t, m, onMain(map[string][]sarif.Result{"sast": {
		codeFinding("api", "r1", "P1", "a.go"),
		codeFinding("api", "r2", "P2", "b.go"),
		codeFinding("api", "r3", "P1", "c.go"),
	}}), perAction)
	if got := m.item(3).Title; got != "renamed by somebody" {
		t.Errorf("a child whose priority held was retitled %q", got)
	}
	if got := m.item(4).Title; got != "P1 · Fix r3" {
		t.Errorf("a child whose priority changed is titled %q", got)
	}
	if !strings.Contains(m.item(4).Body, "<!-- draugr:priority P1 -->") {
		t.Errorf("the child's body keeps the old priority\n%s", m.item(4).Body)
	}
}

func TestAnActionBelowTheGateStillGetsAChild(t *testing.T) {
	m := newMemTracker()
	data := threeRules()
	data.Gate = report.GateSettings{FailOnPriority: "P1"}
	track(t, m, data, perAction)
	if n := len(m.kidsOf(1)); n != 3 {
		t.Errorf("children = %d, want one per action at any priority", n)
	}
}

func TestMinPriorityLimitsTheChildren(t *testing.T) {
	m := newMemTracker()
	cfg := perAction
	cfg.MinPriority = "P2"
	track(t, m, threeRules(), cfg)
	if got := m.titles(m.kidsOf(1)); !slices.Equal(got, []string{"P1 · Fix r1", "P2 · Fix r2"}) {
		t.Errorf("children = %q", got)
	}
}

func TestAClosedParentIsReplacedAndItsChildrenMoveToTheNewOne(t *testing.T) {
	m := newMemTracker()
	track(t, m, threeRules(), perAction)
	m.item(1).Open = false

	track(t, m, threeRules(), perAction)
	parents := m.parents()
	if len(parents) != 1 || parents[0].Number != 5 {
		t.Fatalf("parents = %v", m.titles(parents))
	}
	for n := int64(2); n <= 4; n++ {
		old := m.item(n)
		if old.Open || old.Reason != closedUntracked || len(old.Comments) != 1 ||
			old.Comments[0] != "Its parent is closed. A child of #5 replaces it." {
			t.Errorf("orphan #%d: open %v, comments %q", n, old.Open, old.Comments)
		}
	}
	if n := len(m.kidsOf(5)); n != 3 {
		t.Errorf("children of the new parent = %d, want 3", n)
	}
}

func TestADuplicateChildAndParentClose(t *testing.T) {
	m := newMemTracker()
	track(t, m, threeRules(), perAction)
	// A second copy of the first child and of the parent, as two concurrent runs would leave.
	dup := m.copyOf(2)
	parentDup := m.copyOf(1)

	track(t, m, threeRules(), perAction)
	if m.item(dup).Open || m.item(dup).Reason != closedDuplicate {
		t.Errorf("duplicate child left open")
	}
	if m.item(parentDup).Open || m.item(parentDup).Comments[0] != "Duplicate of #1." {
		t.Errorf("duplicate parent: %+v", m.item(parentDup))
	}
}

func TestSwitchingTheKindOfChildClosesTheOldOnes(t *testing.T) {
	m := newMemTracker()
	track(t, m, threeRules(), perAction)

	perControl := saga.PublisherConfig{Children: saga.ChildrenControls}
	track(t, m, threeRules(), perControl)
	for n := int64(2); n <= 4; n++ {
		if it := m.item(n); it.Open || it.Comments[0] != "The publisher's `children` is now `controls`." {
			t.Errorf("per-action child #%d: open %v, comments %q", n, it.Open, it.Comments)
		}
	}
	kids := m.kidsOf(1)
	if got := m.titles(kids); !slices.Equal(got, []string{"P1 · sast"}) {
		t.Fatalf("children = %q", got)
	}
	for _, line := range []string{"**P1** · `sast` · 3 findings · gate P1", "Fix r2", "an action for this control."} {
		if !strings.Contains(kids[0].Body, line) {
			t.Errorf("control child lacks %q\n%s", line, kids[0].Body)
		}
	}

	track(t, m, threeRules(), saga.PublisherConfig{})
	if it := kids[0]; it.Open || it.Comments[0] != "The publisher's `children` is now `none`." {
		t.Errorf("control child: open %v, comments %q", it.Open, it.Comments)
	}
	if p := m.item(1); !p.Open || !strings.Contains(p.Body, "Fix r1") {
		t.Errorf("parent after children: none\n%s", p.Body)
	}
}

func TestAControlChildClosesWhenItsControlReportsNoAction(t *testing.T) {
	m := newMemTracker()
	perControl := saga.PublisherConfig{Children: saga.ChildrenControls}
	two := onMain(map[string][]sarif.Result{
		"sast": {codeFinding("api", "r1", "P1", "a.go")},
		"sca":  {upgradeFinding("api", "CVE-1", "P2")},
	})
	track(t, m, two, perControl)
	if got := m.titles(m.kidsOf(1)); !slices.Equal(got, []string{"P1 · sast", "P2 · sca"}) {
		t.Fatalf("children = %q", got)
	}
	sca := m.kidsOf(1)[1]

	track(t, m, onMain(map[string][]sarif.Result{
		"sast": {codeFinding("api", "r1", "P1", "a.go")},
		"sca":  nil,
	}), perControl)
	if sca.Open || sca.Comments[0] != "The run reports no action for `sca`." {
		t.Errorf("sca child: open %v, comments %q", sca.Open, sca.Comments)
	}
}

func TestMaxChildrenPerControlNamesControls(t *testing.T) {
	m := newMemTracker()
	cfg := saga.PublisherConfig{Children: saga.ChildrenControls, MaxChildren: new(1)}
	track(t, m, onMain(map[string][]sarif.Result{
		"sast": {codeFinding("api", "r1", "P1", "a.go")},
		"sca":  {upgradeFinding("api", "CVE-1", "P2")},
	}), cfg)
	lead := "1 of 2 controls has an item. The other control's actions are listed below and get an item as open items close, since `maxChildren` is 1."
	if p := m.item(1); !strings.Contains(p.Body, lead) {
		t.Errorf("parent lacks %q\n%s", lead, p.Body)
	}
}

func TestEachSplitPartIsItsOwnFamily(t *testing.T) {
	m := newMemTracker()
	cfg := perAction
	cfg.Split = saga.SplitComponent
	data := onMain(map[string][]sarif.Result{"sast": {
		codeFinding("api", "r1", "P1", "a.go"),
		codeFinding("web", "r2", "P1", "b.go"),
	}})
	track(t, m, data, cfg)
	parents := m.parents()
	if len(parents) != 2 {
		t.Fatalf("parents = %q", m.titles(parents))
	}
	for _, p := range parents {
		if n := len(m.kidsOf(p.Number)); n != 1 {
			t.Errorf("%s has %d children, want 1", p.Title, n)
		}
	}

	// web leaves the run: its child closes, then its parent.
	data.Labels = map[string]map[string]string{"api": {"team": "payments"}}
	cr := data.Run.Controls["sast"]
	cr.Report.Results = cr.Report.Results[:1]
	data.Run.Controls["sast"] = cr
	track(t, m, data, cfg)
	if n := len(m.openOnes()); n != 2 {
		t.Errorf("open items after web left = %d, want 2", n)
	}
	for _, it := range m.items {
		if it.Open {
			continue
		}
		if want := []string{"The run no longer includes component `web`."}; !slices.Equal(it.Comments, want) || it.Reason != closedUntracked {
			t.Errorf("#%d %s: comments %q, reason %v", it.Number, it.Title, it.Comments, it.Reason)
		}
	}
}

func TestAChildKeepsTheFactsOfItsOwnFindings(t *testing.T) {
	m := newMemTracker()
	cfg := perAction
	cfg.LabelBy = []string{"priority", "control"}
	track(t, m, onMain(map[string][]sarif.Result{
		"sast": {codeFinding("api", "r1", "P1", "a.go")},
		"sca":  {upgradeFinding("api", "CVE-1", "P3")},
	}), cfg)
	kids := m.kidsOf(1)
	if len(kids) != 2 {
		t.Fatalf("children = %d", len(kids))
	}
	if l := kids[1].Labels; !slices.Contains(l, "draugr:priority:P3") || !slices.Contains(l, "draugr:control:sca") || slices.Contains(l, "draugr:control:sast") {
		t.Errorf("sca child labels = %q", l)
	}
}

func TestAFailedChildCreateStopsTheFamily(t *testing.T) {
	m := newMemTracker()
	m.fail = "create P2"
	cfg := perAction
	cfg.Kind = "github-issue"
	err := trackIssues(context.Background(), m, threeRules(), cfg)
	if err == nil || !strings.Contains(err.Error(), "create P2") {
		t.Fatalf("err = %v", err)
	}
	if n := len(m.kidsOf(1)); n != 1 {
		t.Errorf("children = %d, want the one created before the failure", n)
	}
}

func TestSplitMarkerParts(t *testing.T) {
	for _, c := range []struct{ in, parent, field string }{
		{"<!-- draugr:issue v1 project=demo -->", "<!-- draugr:issue v1 project=demo -->", ""},
		{"<!-- draugr:issue v1 project=demo action=0123 -->", "<!-- draugr:issue v1 project=demo -->", "action=0123"},
		{"<!-- draugr:issue v1 project=demo child=sca -->", "<!-- draugr:issue v1 project=demo -->", "child=sca"},
		{"<!--x-->", "<!--x-->", ""},
	} {
		p, f := splitMarker(c.in)
		if p != c.parent || f != c.field {
			t.Errorf("splitMarker(%q) = %q, %q", c.in, p, f)
		}
	}
	if got := childMarker("<!-- draugr:issue v1 -->", "child=sca"); got != "<!-- draugr:issue v1 child=sca -->" {
		t.Errorf("childMarker = %q", got)
	}
}

func TestChildLeadVariants(t *testing.T) {
	f := markdownFormat{}
	for _, c := range []struct {
		kind               string
		have, total, limit int
		reason             childReason
		want               string
	}{
		{childrenActions, 3, 3, 20, childrenCapped, ""},
		{childrenActions, 1, 1, 20, childrenComplete, ""},
		{childrenActions, 20, 46, 20, childrenCapped,
			"20 of 46 actions have an item. The other 26 are listed below and get an item as open items close, since `maxChildren` is 20."},
		{childrenActions, 0, 2, 20, childrenPaced,
			"0 of 2 actions have an item. The other 2 are listed below and get an item on the next run."},
		{childrenControls, 1, 3, 1, childrenCapped,
			"1 of 3 controls has an item. The other 2 controls' actions are listed below and get an item as open items close, since `maxChildren` is 1."},
	} {
		if got := childLead(f, c.kind, c.have, c.total, c.reason, c.limit); got != c.want {
			t.Errorf("childLead(%s, %d, %d) =\n%q\nwant\n%q", c.kind, c.have, c.total, got, c.want)
		}
	}
}

func TestAnActionChildCutsItsFindingsToFit(t *testing.T) {
	var rs []sarif.Result
	for i := range 40 {
		rs = append(rs, codeFinding("api", "r1", "P1", fmt.Sprintf("file%02d.go", i)))
	}
	data := onMain(map[string][]sarif.Result{"sast": rs})
	entry := issueEntry{Children: childrenActions, MaxChildren: 100}
	part := onlyPart(t, data, entry)
	s := &tracking{t: newMemTracker(), data: data, entry: entry, project: "demo", scope: "all"}
	u := childUnits(childrenActions, newIssueBody(data, "all", entry, part).Actions)[0]
	full := s.childBody(part, u)

	b := newIssueBody(data, "all", entry, part)
	b.Marker = childMarker(b.Marker, u.Field)
	b.Controls, b.Actions = nil, u.Actions
	b.Child = &childHead{Priority: "P1", Control: "sast", Clears: 40, Gate: "P1", Action: &u.Actions[0]}
	budget := len([]rune(full)) - 200
	got := b.render(markdownFormat{}, budget)
	if n := len([]rune(got)); n > budget {
		t.Fatalf("child is %d characters, budget %d", n, budget)
	}
	if !strings.Contains(got, "more, left out for size, listed in [job 77]") {
		t.Errorf("child does not say findings were left out\n%s", got)
	}
}

func TestAChildNamesItsControlsOwnGate(t *testing.T) {
	m := newMemTracker()
	data := onMain(map[string][]sarif.Result{
		"sast": {codeFinding("api", "r1", "P1", "a.go")},
		"sca":  {upgradeFinding("api", "CVE-1", "P2")},
	})
	data.Gate = report.GateSettings{FailOnPriority: "P1", PerControlBand: map[string]string{"sca": "P2"}}
	track(t, m, data, saga.PublisherConfig{Children: saga.ChildrenControls})
	kids := m.kidsOf(1)
	if len(kids) != 2 {
		t.Fatalf("children = %d", len(kids))
	}
	if !strings.Contains(kids[0].Body, "· gate P1") || !strings.Contains(kids[1].Body, "· gate P2") {
		t.Errorf("gates:\n%s\n---\n%s", kids[0].Body, kids[1].Body)
	}
}

func TestAChildNamesItsFixOnlyWhenThereIsOne(t *testing.T) {
	head := func(fixed ...string) string {
		b := issueBody{Marker: "<!-- m -->", Child: &childHead{
			Priority: "P1", Control: "sca", Clears: 2, Gate: "P1",
			Action: &report.Action{FixedVersions: fixed},
		}}
		return strings.Join(b.head(markdownFormat{}), "\n")
	}
	if got := head("3.1.6"); !strings.Contains(got, "**P1** · `sca` · 2 findings · gate P1 · fixed in `3.1.6`") {
		t.Errorf("one release is not named\n%s", got)
	}
	for _, fixed := range [][]string{nil, {"2.10.1", "3.1.6"}} {
		if got := head(fixed...); strings.Contains(got, "fixed in") {
			t.Errorf("%d releases are listed in the head\n%s", len(fixed), got)
		}
	}
}

func TestAFindingRowOpensWithItsUpgradeWhicheverScannerWroteIt(t *testing.T) {
	const up = "jinja2 2.10 → 2.10.1"
	for _, c := range []struct{ name, message, want string }{
		{"a scanner that states the upgrade", up + ": sandbox escape", up + ": sandbox escape"},
		{"a scanner that never states it", "sandbox escape", up + ": sandbox escape"},
		{"a finding with no message", "", up},
	} {
		got := findingMessage(report.ActionFinding{Message: c.message, Upgrade: up})
		if got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := findingMessage(report.ActionFinding{Message: " a SQL query built from input "}); got != "a SQL query built from input" {
		t.Errorf("a finding with no upgrade: %q", got)
	}
}
