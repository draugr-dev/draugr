package report

import (
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	repoAPI    = "https://github.com/acme/api.git"
	repoShared = "https://github.com/acme/shared.git"
	repoWorker = "https://github.com/acme/worker.git"
)

// lineResult is a sast result at a line, as a merged results.sarif carries it.
func lineResult(tool, rule, prio, component, repo, uri string, line int, msg string) sarif.Result {
	return sarif.Result{
		Control: "sast", Tool: tool, RuleID: rule, Priority: prio, Level: sarif.LevelError,
		Component: component, Repository: repo, Message: msg,
		Location: sarif.Location{URI: uri, StartLine: line},
	}
}

// codeLines is a run across two components and three repositories: two rules at one line, one rule
// at two lines, the same path and line in a second repository and in a second component sharing the
// first's, and an imported SARIF file's finding that names no repository.
func codeLines() ([]sarif.Result, map[string]sarif.Rule) {
	shell := "subprocess call with shell=True identified, security issue."
	inject := "Detected user input entering a `subprocess` call unsafely."
	eval := "Detected the use of eval()."
	rs := []sarif.Result{
		lineResult("Bandit", "B602", "P1", "api", repoAPI, "app/app.py", 23, shell),
		lineResult("Semgrep OSS", "python.flask.security.injection.subprocess-injection.subprocess-injection",
			"P1", "api", repoAPI, "app/app.py", 23, inject),
		lineResult("Semgrep OSS", "python.lang.security.audit.eval-detected.eval-detected", "P3",
			"api", repoAPI, "app/app.py", 30, eval),
		lineResult("Semgrep OSS", "python.lang.security.audit.eval-detected.eval-detected", "P3",
			"api", repoAPI, "app/app.py", 31, eval),
		lineResult("Bandit", "B602", "P1", "api", repoShared, "app/app.py", 23, shell),
		lineResult("Bandit", "B602", "P2", "web", repoShared, "app/app.py", 23, shell),
		lineResult("Semgrep OSS", "go.lang.security.audit.dangerous-exec-command", "P2",
			"worker", repoWorker, "main.go", 12, "Detected non-static command inside Command."),
		// Imported: a path and no repository. The worker's other findings name one repository, so
		// this one is placed in it and joins the line above.
		lineResult("gosec", "G204", "P2", "worker", "", "main.go", 12, "Subprocess launched with a potential tainted input."),
	}
	rules := map[string]sarif.Rule{
		"B602": {HelpURI: "https://bandit.readthedocs.io/en/latest/plugins/b602.html"},
	}
	return rs, rules
}

// The diff and the scan list a line of code as one action only while both group, title and list
// rules the same way. LineOf over what LineKey groups has to describe exactly the actions the fix
// list makes from the same results.
func TestLineOfDescribesTheFixListsOwnActions(t *testing.T) {
	rs, rules := codeLines()

	placed := PlaceLines(rs)
	var order []string
	groups := map[string][]sarif.Result{}
	for _, res := range placed {
		key, ok := LineKey(res)
		if !ok {
			t.Fatalf("%s at %s is a sast finding at a line and has no key", res.RuleID, locationOf(res))
		}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], res)
	}

	actions := ActionsFor(map[string]sarif.Report{"sast": {Results: rs, Rules: rules}})
	if len(actions) != len(order) {
		t.Fatalf("the fix list has %d actions and LineKey %d groups", len(actions), len(order))
	}
	byKey := map[string]Action{}
	for _, a := range actions {
		byKey[a.Key] = a
	}
	for _, key := range order {
		line := LineOf(rules, groups[key])
		a, ok := byKey[key]
		if !ok {
			t.Fatalf("LineKey grouped %s at %s, which is no action in the fix list", line.Title, line.Location)
		}
		if line.Key != a.Key || line.Title != a.Title || line.Summary != a.Summary || line.Component != a.Component {
			t.Errorf("LineOf %+v disagrees with the fix list's %+v", line, a)
		}
		var ids []string
		for _, g := range line.Rules {
			for _, r := range g.Rules {
				ids = append(ids, r.ID)
			}
		}
		if !reflect.DeepEqual(ids, a.RuleIDs) {
			t.Errorf("%s: rules %v, the fix list lists %v", line.Location, ids, a.RuleIDs)
		}
		if len(groups[key]) != a.Clears {
			t.Errorf("%s: %d results, the fix list clears %d", line.Location, len(groups[key]), a.Clears)
		}
	}
}

// Two rules at one line are one line; one rule at two lines is two; the same path in two
// repositories, or in two components sharing one, is two.
func TestLineKeySeparatesWhatIsTwoEdits(t *testing.T) {
	rs, _ := codeLines()
	placed := PlaceLines(rs)
	key := func(i int) string {
		k, _ := LineKey(placed[i])
		return k
	}
	if key(0) != key(1) {
		t.Error("two rules at one line are two keys")
	}
	if key(2) == key(3) {
		t.Error("one rule at two lines is one key")
	}
	if key(0) == key(4) {
		t.Error("the same line in two repositories is one key")
	}
	if key(4) == key(5) {
		t.Error("the same line in two components is one key")
	}
	if key(6) != key(7) {
		t.Error("an imported finding was not placed in its component's repository")
	}
}

func TestPlaceLinesCopiesAndLeavesTheUnplaceableAlone(t *testing.T) {
	rs, _ := codeLines()
	placed := PlaceLines(rs)
	if rs[7].Repository != "" {
		t.Error("PlaceLines changed the caller's result")
	}
	if placed[7].Repository != repoWorker {
		t.Errorf("placed in %q, want %q", placed[7].Repository, repoWorker)
	}
	// api names two repositories, so a path alone does not say which one it is in.
	orphan := lineResult("gosec", "G204", "P2", "api", "", "app/app.py", 23, "x")
	if got := PlaceLines(append(rs, orphan))[len(rs)].Repository; got != "" {
		t.Errorf("a component with two repositories placed a path in %q", got)
	}
}

func TestLineKeyIsOnlyForCodeAtALine(t *testing.T) {
	for name, res := range map[string]sarif.Result{
		"no line":       {Control: "sast", RuleID: "r", Location: sarif.Location{URI: "a.py"}},
		"another check": {Control: "iac", RuleID: "r", Location: sarif.Location{URI: "Dockerfile", StartLine: 3}},
	} {
		if key, ok := LineKey(res); ok || key != "" {
			t.Errorf("%s: keyed as a line, %q", name, key)
		}
	}
}

func TestLineOfTitlesAndListsTheRules(t *testing.T) {
	rs, rules := codeLines()
	line := LineOf(rules, rs[:2])
	if !strings.HasPrefix(line.Title, "Fix “") {
		t.Errorf("title %q does not quote a scanner", line.Title)
	}
	// The longer description titles the line, and its rule leads the list.
	want := []LineRules{
		{Tool: "Bandit", Rules: []LineRule{{
			ID: "B602", Name: "B602", HelpURI: "https://bandit.readthedocs.io/en/latest/plugins/b602.html",
		}}},
		{Tool: "Semgrep", Rules: []LineRule{{
			ID:   "python.flask.security.injection.subprocess-injection.subprocess-injection",
			Name: "subprocess-injection",
		}}},
	}
	if line.Title != "Fix “subprocess call with shell=True identified, security issue”" {
		t.Errorf("title %q", line.Title)
	}
	if !reflect.DeepEqual(line.Rules, want) {
		t.Errorf("rules %+v, want %+v", line.Rules, want)
	}
	if line.Where(false) != "app/app.py:23" || line.Where(true) != "acme/api app/app.py:23" {
		t.Errorf("where %q, %q", line.Where(false), line.Where(true))
	}
	if (CodeLine{Location: "a.py:1"}).Where(true) != "a.py:1" {
		t.Error("a line with no repository named one")
	}
	if !reflect.DeepEqual(LineOf(rules, nil), CodeLine{}) {
		t.Error("no results gave a line")
	}
}
