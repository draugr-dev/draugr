package report

import (
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding's movement is every input that moved its band. The cases that look like a movement and
// are not matter as much as the ones that are: a verdict exploitation outranked, a verdict on a
// finding with nowhere lower to go, and a path in a commit all leave the band where severity put
// it.
func TestAFindingHoldsEveryInputThatMovedItsBand(t *testing.T) {
	kev := &sarif.Escalation{Signal: "kev", From: "high", To: "critical"}
	epss := &sarif.Escalation{Signal: "epss", From: "medium", To: "high", Detail: "EPSS 0.87"}
	lowered := &sarif.Reachability{State: sarif.ReachabilityUnreachable, RankedAs: "low"}
	// No RankedAs: the verdict was recorded and changed nothing, either because a signal outranked
	// it or because the finding was already as low as it goes.
	standing := &sarif.Reachability{State: sarif.ReachabilityUnreachable}
	for _, c := range []struct {
		name, want, mark string
		f                finding
	}{
		{"raised by KEV", "escalation", "KEV", finding{escalation: kev}},
		{"floored", "floor", "floor", finding{priorityFloor: "a leaked credential is high priority wherever it is found"}},
		{"lowered", "unreachable", "unreachable", finding{reachability: lowered}},
		{"raised by EPSS over a verdict it outranked", "escalation", "EPSS 0.87", finding{escalation: epss, reachability: standing}},
		{"a verdict on a finding at the lowest band", "untouched", "", finding{reachability: standing}},
		{"raised and floored", "escalation floor", "KEV", finding{escalation: kev, priorityFloor: "floor"}},
		{"floored and lowered", "floor unreachable", "floor", finding{priorityFloor: "floor", reachability: lowered}},
		{"found in history and nothing else", "untouched", "history", finding{historical: true}},
		{"moved by nothing", "untouched", "", finding{}},
	} {
		got := toHTMLFinding(c.f)
		if got.Movement != c.want {
			t.Errorf("%s: movement %q, want %q", c.name, got.Movement, c.want)
		}
		// The mark stays the one movedBy picks, so the row and the filter read the same facts and
		// only the filter holds all of them.
		if got.MovedLabel != c.mark {
			t.Errorf("%s: mark %q, want %q", c.name, got.MovedLabel, c.mark)
		}
	}
}

// movementRun is two components, because a count that collapsed per component would still be right
// with one. Each input moves at least one finding, one finding is moved by two, one historical
// finding is moved by nothing else, and one verdict is outranked by the signal that raised it.
func movementRun() Data {
	kev := &sarif.Escalation{Signal: "kev", From: "high", To: "critical"}
	epss := &sarif.Escalation{Signal: "epss", From: "medium", To: "high", Detail: "EPSS 0.87"}
	floor := "a leaked credential is high priority wherever it is found"
	return Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Tool: "trivy", Priority: "P1", Component: "api",
				Escalation: kev},
			{RuleID: "CVE-2", Level: sarif.LevelWarning, Tool: "trivy", Priority: "P2", Component: "api",
				Escalation:   epss,
				Reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable}},
			{RuleID: "CVE-3", Level: sarif.LevelError, Tool: "trivy", Priority: "P4", Component: "worker",
				Reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable, RankedAs: "low"}},
			{RuleID: "CVE-4", Level: sarif.LevelNote, Tool: "trivy", Priority: "P4", Component: "worker",
				Reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable}},
		}}},
		"secrets": {Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
			{RuleID: "aws-key", Level: sarif.LevelError, Tool: "gitleaks", Priority: "P1", Component: "api",
				PriorityFloor: floor},
			{RuleID: "gcp-key", Level: sarif.LevelError, Tool: "gitleaks", Priority: "P1", Component: "worker",
				PriorityFloor: floor, Escalation: epss},
			{RuleID: "old-key", Level: sarif.LevelError, Tool: "gitleaks", Priority: "P2", Component: "worker",
				Historical: true},
		}}},
		"sast": {Report: sarif.Report{Tool: "semgrep", Results: []sarif.Result{
			{RuleID: "raw-sql", Level: sarif.LevelWarning, Tool: "semgrep", Priority: "P3", Component: "api"},
		}}},
	}}}
}

// movementMenuOf is the Movement menu's markup and nothing after it, so an assertion about its
// options cannot be met by another menu or by a row further down the page.
func movementMenuOf(t *testing.T, page string) string {
	t.Helper()
	return section(t, page, `<span class="menu-anchor folded" data-k="movement"`, `  </div>
</span>`)
}

var findingRow = regexp.MustCompile(`<div class="f" [^>]*data-movement="([^"]*)"[^>]*data-m="([^"]*)"[^>]*data-q="([^" ]*)`)

// Each row carries its whole set of movements for the filter to read, and the menu counts each
// finding under every input that moved it, so the counts overlap where one finding was moved twice.
func TestTheMovementMenuCountsEveryFindingUnderEachInputThatMovedIt(t *testing.T) {
	page := renderHTML(t, movementRun())

	rows := map[string][2]string{}
	for _, m := range findingRow.FindAllStringSubmatch(page, -1) {
		rows[m[3]] = [2]string{m[1], m[2]}
	}
	for rule, want := range map[string][2]string{
		"cve-1":   {"escalation", "api"},
		"cve-2":   {"escalation", "api"},
		"cve-3":   {"unreachable", "worker"},
		"cve-4":   {"untouched", "worker"},
		"aws-key": {"floor", "api"},
		"gcp-key": {"escalation floor", "worker"},
		"old-key": {"untouched", "worker"},
		"raw-sql": {"untouched", "api"},
	} {
		if got, ok := rows[rule]; !ok {
			t.Errorf("%s: no row", rule)
		} else if got != want {
			t.Errorf("%s: movement and component %q, want %q", rule, got, want)
		}
	}

	menu := movementMenuOf(t, page)
	for _, want := range []string{
		`<input type="checkbox" data-k="movement" value="escalation" data-label="raised by a signal">raised by a signal</span>
        <span class="c">3</span>`,
		`<input type="checkbox" data-k="movement" value="floor" data-label="floored by a control">floored by a control</span>
        <span class="c">2</span>`,
		`<input type="checkbox" data-k="movement" value="unreachable" data-label="lowered as unreachable">lowered as unreachable</span>
        <span class="c">1</span>`,
		`<input type="checkbox" data-k="movement" value="untouched" data-label="ranked from severity alone">ranked from severity alone</span>
        <span class="c">3</span>`,
	} {
		if !strings.Contains(menu, want) {
			t.Errorf("the Movement menu is missing\n%s\nin\n%s", want, menu)
		}
	}
	// The values in the order the menu offers them everywhere else.
	order := []string{"raised by a signal", "floored by a control", "lowered as unreachable", "ranked from severity alone"}
	for i := 1; i < len(order); i++ {
		if strings.Index(menu, order[i-1]) > strings.Index(menu, order[i]) {
			t.Errorf("%q is offered after %q", order[i-1], order[i])
		}
	}
	if strings.Contains(menu, "history") {
		t.Error("history is offered as a movement, and it moves no band")
	}

	// Folded with the secondary menus, after Severity, and marked as holding a set per row.
	if !strings.Contains(page, `<span class="menu-anchor folded" data-k="movement" data-multi>`) {
		t.Error("the Movement menu is not folded, or not marked set-valued")
	}
	if strings.Index(page, `data-k="s">`) > strings.Index(page, `data-k="movement"`) ||
		strings.Index(page, `data-k="movement"`) > strings.Index(page, `data-k="m">`) {
		t.Error("the Movement menu is not between Severity and Component")
	}
}

// Movement is Draugr's own vocabulary, so a run nothing moved still offers every value, with a zero
// that cannot be ticked, as Priority and Severity do.
func TestTheMovementMenuOffersEveryValueWithAZero(t *testing.T) {
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Report: sarif.Report{Tool: "semgrep", Results: []sarif.Result{
			{RuleID: "raw-sql", Level: sarif.LevelWarning, Tool: "semgrep", Priority: "P3", Component: "api"},
			{RuleID: "xss", Level: sarif.LevelWarning, Tool: "semgrep", Priority: "P3", Component: "web"},
		}}},
	}}}
	menu := movementMenuOf(t, renderHTML(t, d))
	for _, want := range []string{
		`value="escalation" data-label="raised by a signal" disabled>raised by a signal</span>
        <span class="c">0</span>`,
		`value="floor" data-label="floored by a control" disabled>floored by a control</span>
        <span class="c">0</span>`,
		`value="unreachable" data-label="lowered as unreachable" disabled>lowered as unreachable</span>
        <span class="c">0</span>`,
		`value="untouched" data-label="ranked from severity alone">ranked from severity alone</span>
        <span class="c">2</span>`,
	} {
		if !strings.Contains(menu, want) {
			t.Errorf("the Movement menu is missing\n%s\nin\n%s", want, menu)
		}
	}
}

// The menus whose value is their own name are drawn as before: no label, no set marker.
func TestAMenuWithoutLabelsShowsItsValues(t *testing.T) {
	page := renderHTML(t, movementRun())
	for _, want := range []string{
		`<span class="menu-anchor folded" data-k="s">`,
		`<input type="checkbox" data-k="sc" value="gitleaks">gitleaks</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page is missing %q", want)
		}
	}
}
