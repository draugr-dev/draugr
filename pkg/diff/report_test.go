package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// twoComponentsOneCVE is the case a pull-request comment on a monorepo actually produces: the
// same dependency reached from two services. The fingerprint separates them, so they are two
// findings, and without the component they are two rows identical in every visible column.
func twoComponentsOneCVE() Result {
	return Result{New: []sarif.Result{
		{RuleID: "CVE-2019-20477", Level: sarif.LevelError, Priority: "P1", Tool: "trivy",
			Component: "payments", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 4}},
		{RuleID: "CVE-2019-20477", Level: sarif.LevelError, Priority: "P1", Tool: "trivy",
			Component: "internal-tool", Location: sarif.Location{URI: "app/requirements.txt", StartLine: 4}},
	}}
}

func TestMarkdownNamesTheComponent(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "markdown", twoComponentsOneCVE(), Options{}); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if !strings.Contains(got, "| Change | Priority | Severity | Rule | Scanner | Component | Location |") {
		t.Errorf("missing the column:\n%s", got)
	}
	for _, want := range []string{"payments", "internal-tool"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q, the two rows are indistinguishable:\n%s", want, got)
		}
	}
}

func TestConsoleNamesTheComponent(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "console", twoComponentsOneCVE(), Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"payments", "internal-tool"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q:\n%s", want, b.String())
		}
	}
}

func TestNoComponentColumnWhenNobodyHasOne(t *testing.T) {
	// A single-component project would get a column repeating itself, the rule the scan report
	// already follows.
	r := Result{New: []sarif.Result{{RuleID: "x", Level: sarif.LevelError, Tool: "trivy"}}}
	var b bytes.Buffer
	if err := Render(&b, "markdown", r, Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Component") {
		t.Errorf("nothing to say:\n%s", b.String())
	}
}

func TestComponentColumnIsDecidedFromEveryState(t *testing.T) {
	// One header decision covers all four lists, so each has to be consulted. A change whose only
	// news is an acceptance ending used to lose the column entirely, which is the case where the
	// question "is this mine" is hardest to answer from anything else on the row.
	r := Result{
		Unaccepted: []sarif.Result{{RuleID: "x", Level: sarif.LevelError, Tool: "trivy", Component: "web"}},
		Fixed:      []sarif.Result{{RuleID: "y", Level: sarif.LevelError, Tool: "trivy", Component: "payments"}},
	}
	var b bytes.Buffer
	if err := Render(&b, "markdown", r, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| web |", "| payments |"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %s, the rows are indistinguishable:\n%s", want, b.String())
		}
	}
}

func TestDiffSpeaksTheSameSeverityAsTheScanReport(t *testing.T) {
	// A diff is read beside the scan report it came from. Printing SARIF's wire vocabulary made
	// one finding read as "error" here and "critical" there, leaving the reader translating
	// between two ladders to answer one question: did this pull request make things worse.
	crit := sarif.Result{
		Tool: "Trivy", RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1",
		Score: 9.8, HasScore: true,
		Location: sarif.Location{URI: "app/requirements.txt", StartLine: 3},
	}
	r := Result{New: []sarif.Result{crit}}

	for _, format := range []string{"console", "markdown"} {
		var b bytes.Buffer
		if err := Render(&b, format, r, Options{}); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		out := b.String()
		if !strings.Contains(out, "critical") {
			t.Errorf("%s: a 9.8 finding is critical, not what SARIF calls it:\n%s", format, out)
		}
		if strings.Contains(out, "error") {
			t.Errorf("%s: still printing the SARIF level:\n%s", format, out)
		}
	}
}

func TestDiffHeadlineNamesOnlyTheStatesThatHappened(t *testing.T) {
	// "0 unaccepted, 0 accepted, 2 new" makes a reader scan past two zeroes to find the number that
	// matters, and a clean diff should not read as a list of things that are fine.
	r := Result{
		New:        []sarif.Result{{RuleID: "a", Level: sarif.LevelError}},
		Unaccepted: []sarif.Result{{RuleID: "b", Level: sarif.LevelWarning}},
		Unchanged:  []sarif.Result{{RuleID: "c"}},
	}
	got := strings.Join(headline(r, false), " · ")
	for _, want := range []string{"1 new", "1 unaccepted", "1 unchanged"} {
		if !strings.Contains(got, want) {
			t.Errorf("headline %q is missing %q", got, want)
		}
	}
	for _, unwanted := range []string{"accepted", "fixed"} {
		if strings.Contains(got, "0 "+unwanted) {
			t.Errorf("headline names a state that did not happen: %q", got)
		}
	}
	// Marked in a forge comment and not in a terminal. A terminal has the priority ramp to find a
	// row by; a comment has one line of a paragraph somebody skims.
	if marked := strings.Join(headline(r, true), " · "); !strings.Contains(marked, "🔺 1 new") {
		t.Errorf("the comment's headline carries no mark: %q", marked)
	}
	if strings.ContainsAny(got, "🔺⚠️🤝✅") {
		t.Errorf("the terminal headline should carry no emoji: %q", got)
	}
	// Unchanged is always named, because zero there is the answer rather than noise: a diff of two
	// empty reports has to say it compared something.
	if clean := strings.Join(headline(Result{}, false), " · "); clean != "0 unchanged" {
		t.Errorf("a clean diff should read clean, got %q", clean)
	}
}

// The SARIF diff carries the new findings and only those.
//
// The fixture has all three kinds on purpose: with new findings alone, an implementation that
// emits everything it was given is indistinguishable from one that selects. Fixed and unchanged
// are what a pull request's reviewer did not cause, and shipping them is the noise this format
// exists to remove.
func TestRenderSARIFCarriesOnlyTheNewFindings(t *testing.T) {
	r := Result{
		New:       []sarif.Result{{RuleID: "NEW-1", Level: sarif.LevelError, Message: "introduced here"}},
		Fixed:     []sarif.Result{{RuleID: "GONE-1", Level: sarif.LevelError, Message: "no longer present"}},
		Unchanged: []sarif.Result{{RuleID: "OLD-1", Level: sarif.LevelWarning, Message: "was already there"}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, "sarif", r, Options{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	var ids []string
	for _, run := range doc.Runs {
		for _, res := range run.Results {
			ids = append(ids, res.RuleID)
		}
	}
	if len(ids) != 1 || ids[0] != "NEW-1" {
		t.Errorf("results = %v, want just the new finding", ids)
	}
}

// sarif is in the advertised list, so `--format` help and the unknown-format error stay true.
func TestFormatsAdvertisesSARIF(t *testing.T) {
	if !slices.Contains(Formats(), "sarif") {
		t.Errorf("Formats() = %v, missing sarif", Formats())
	}
}

// A rule id in a table is a string to copy into a search box. Linked, it is the answer.
//
// Both halves are checked because they come from different places: a scanner that published a
// helpUri gets its own advisory, and one that published nothing gets whatever a well-known
// identifier scheme implies. Getting the first wrong sends a reader to a generic page when the
// scanner named a specific one.
func TestMarkdownLinksRulesToWhereTheyAreExplained(t *testing.T) {
	r := Result{
		New: []sarif.Result{
			{RuleID: "CVE-2018-1000656", Level: sarif.LevelError, Tool: "Trivy"},
			{RuleID: "CVE-2021-99999", Level: sarif.LevelError, Tool: "Trivy"},
			{RuleID: "no-such-scheme", Level: sarif.LevelWarning, Tool: "Semgrep"},
		},
		// Only the first has published metadata; the others fall back or get nothing.
		Rules: map[string]sarif.Rule{
			"CVE-2018-1000656": {HelpURI: "https://avd.aquasec.com/nvd/cve-2018-1000656"},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, "markdown", r, Options{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"[`CVE-2018-1000656`](https://avd.aquasec.com/nvd/cve-2018-1000656)",  // what the scanner said
		"[`CVE-2021-99999`](https://nvd.nist.gov/vuln/detail/CVE-2021-99999)", // derived from the id
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	// Nowhere to send the reader is not a reason to invent a link.
	if strings.Contains(got, "[`no-such-scheme`](") {
		t.Errorf("linked a rule with no known home:\n%s", got)
	}
}

// The SARIF a pull request uploads carries the rules its findings cite.
//
// Without them a code-scanning alert is a bare identifier: no description, and whatever link can
// be guessed from the id's shape rather than the advisory the scanner named. Only the rules the
// new findings actually cite, carrying the other few hundred would put the noise back.
func TestRenderSARIFCarriesTheRulesItsFindingsCite(t *testing.T) {
	r := Result{
		New:   []sarif.Result{{RuleID: "CVE-1", Level: sarif.LevelError}},
		Fixed: []sarif.Result{{RuleID: "CVE-2", Level: sarif.LevelError}},
		Rules: map[string]sarif.Rule{
			"CVE-1": {HelpURI: "https://example.test/cve-1", ShortDescription: "the new one"},
			"CVE-2": {HelpURI: "https://example.test/cve-2", ShortDescription: "the fixed one"},
		},
	}
	var buf bytes.Buffer
	if err := Render(&buf, "sarif", r, Options{}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID      string `json:"id"`
						HelpURI string `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	var ids []string
	for _, run := range doc.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			ids = append(ids, rule.ID)
			if rule.ID == "CVE-1" && rule.HelpURI != "https://example.test/cve-1" {
				t.Errorf("CVE-1 lost the advisory the scanner published: %q", rule.HelpURI)
			}
		}
	}
	if !slices.Equal(ids, []string{"CVE-1"}) {
		t.Errorf("rules = %v, want only the one the new findings cite", ids)
	}
}

// The three views are the same three `scan` takes, and each one is the same table with more or
// less of each row drawn.
func TestTheThreeViewsDrawTheSameTable(t *testing.T) {
	r := Result{New: []sarif.Result{{
		RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy",
		Message: "a sentence explaining the finding",
		Package: &sarif.Package{Name: "urllib3", Version: "2.0.7", FixedVersion: "2.6.0"},
	}}}
	draw := func(v View) string {
		var b strings.Builder
		if err := Render(&b, "console", r, Options{View: v}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	findings, compact, actions := draw(ViewFindings), draw(ViewCompact), draw(ViewActions)
	if !strings.Contains(findings, "a sentence explaining the finding") {
		t.Errorf("the default view drops the finding's own sentence:\n%s", findings)
	}
	if strings.Contains(compact, "a sentence explaining the finding") {
		t.Errorf("compact is one line each, and kept the sentence:\n%s", compact)
	}
	if !strings.Contains(compact, "urllib3 2.0.7") {
		t.Errorf("compact dropped the upgrade, which is the row's only instruction:\n%s", compact)
	}
	if !strings.Contains(actions, "Upgrade urllib3 2.0.7") {
		t.Errorf("actions did not group the finding into something to do:\n%s", actions)
	}
}

// A fixed row names the package that was vulnerable and not a version to move to. The diff knows
// the finding is gone, not how it left: removing the dependency outright produces the same row.
func TestAFixedRowDoesNotAdviseAnUpgrade(t *testing.T) {
	r := Result{Fixed: []sarif.Result{{
		RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy",
		Package: &sarif.Package{Name: "Flask", Version: "0.12.2", FixedVersion: "0.12.3"},
	}}}
	var b strings.Builder
	if err := Render(&b, "console", r, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); !strings.Contains(got, "Flask 0.12.2") || strings.Contains(got, "0.12.3") {
		t.Errorf("a fixed row should name the package and no target:\n%s", got)
	}
}

// Without a gate there is no verdict to state: `draugr diff` reports and exits 0, and a chip would
// be claiming an answer to a question nobody asked.
func TestNoGateMeansNoVerdict(t *testing.T) {
	r := Result{New: []sarif.Result{{RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1"}}}
	var b strings.Builder
	if err := Render(&b, "console", r, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); strings.Contains(got, "FAIL") || strings.Contains(got, "Gate:") {
		t.Errorf("no gate was asked for, so there is no verdict:\n%s", got)
	}

	r.Gate = Gate{FailOnPriority: "P1"}
	r.Tripped = r.GateNew("", "P1")
	var gated strings.Builder
	if err := Render(&gated, "console", r, Options{}); err != nil {
		t.Fatal(err)
	}
	got := gated.String()
	if !strings.Contains(got, "FAIL") {
		t.Errorf("the gate tripped and the verdict does not say so:\n%s", got)
	}
	if !strings.Contains(got, "fails on any P1 this change introduces") {
		t.Errorf("a verdict with no rule beside it cannot be checked:\n%s", got)
	}
}

// --top exists for the bump that introduces forty. It says it held rows back, in the words the
// scan report uses, and only when it did.
func TestTopSaysWhenItHeldRowsBack(t *testing.T) {
	var fs []sarif.Result
	for i := range 5 {
		fs = append(fs, sarif.Result{
			RuleID: fmt.Sprintf("CVE-%d", i), Level: sarif.LevelError, Priority: "P1",
		})
	}
	r := Result{New: fs}

	var all strings.Builder
	if err := Render(&all, "console", r, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := all.String(); strings.Contains(got, "top ") || strings.Contains(got, "not listed") {
		t.Errorf("nothing was held back and the heading claims otherwise:\n%s", got)
	}

	var capped strings.Builder
	if err := Render(&capped, "console", r, Options{Top: 2}); err != nil {
		t.Fatal(err)
	}
	got := capped.String()
	if !strings.Contains(got, "top 2 of 5") {
		t.Errorf("a truncated listing should say so:\n%s", got)
	}
	if !strings.Contains(got, "and 3 changed findings not listed") {
		t.Errorf("a reader cannot tell how much is missing:\n%s", got)
	}
}

// Everything the change touched in one ranking, so a reviewer reads the order once. A fix comes
// last inside a band: it is the one state nobody has to act on.
func TestChangedRanksWorkBeforeGoodNews(t *testing.T) {
	r := Result{
		New:   []sarif.Result{{RuleID: "new", Level: sarif.LevelError, Priority: "P1"}},
		Fixed: []sarif.Result{{RuleID: "fixed", Level: sarif.LevelError, Priority: "P1"}},
	}
	got := r.Changed()
	if len(got) != 2 {
		t.Fatalf("got %d entries, want both states in one list", len(got))
	}
	if got[0].Change != ChangeNew || got[1].Change != ChangeFixed {
		t.Errorf("order = %s then %s, want the work first", got[0].Change, got[1].Change)
	}
}

// A flag that quietly does nothing in one view is the same silence as a scanner that did not run.
func TestTopAppliesToTheActionsViewToo(t *testing.T) {
	var fs []sarif.Result
	for i := range 4 {
		fs = append(fs, sarif.Result{
			RuleID: fmt.Sprintf("CVE-%d", i), Level: sarif.LevelError, Priority: "P1", Control: "sca",
			Package: &sarif.Package{
				Name: fmt.Sprintf("pkg%d", i), Version: "1.0", FixedVersion: "2.0",
			},
		})
	}
	r := Result{New: fs}
	var b strings.Builder
	if err := Render(&b, "console", r, Options{View: ViewActions, Top: 2}); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if !strings.Contains(got, "top 2 of 4 actions") {
		t.Errorf("the actions view ignored --top:\n%s", got)
	}
	if !strings.Contains(got, "2 actions not listed") {
		t.Errorf("a reader cannot tell how much was held back:\n%s", got)
	}
	if strings.Contains(got, "pkg3") {
		t.Errorf("a held-back action was drawn anyway:\n%s", got)
	}
}

// The verb belongs to the change, not to the package. An accepted finding is a decision somebody
// already made, and telling a reviewer to upgrade it is work that is not theirs on a line that
// hides the decision that is.
func TestAnActionNamesWhatTheChangeAsksFor(t *testing.T) {
	pkg := func() *sarif.Package {
		return &sarif.Package{Name: "Flask", Version: "0.12.2", FixedVersion: "0.12.3"}
	}
	r := Result{
		New:        []sarif.Result{{RuleID: "A", Level: sarif.LevelError, Priority: "P1", Package: pkg()}},
		Accepted:   []sarif.Result{{RuleID: "B", Level: sarif.LevelError, Priority: "P1", Package: pkg()}},
		Unaccepted: []sarif.Result{{RuleID: "C", Level: sarif.LevelError, Priority: "P1", Package: pkg()}},
	}
	var b strings.Builder
	if err := Render(&b, "console", r, Options{View: ViewActions}); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{
		"Upgrade Flask 0.12.2",
		"Review the acceptance of Flask 0.12.2",
		"Decide on Flask 0.12.2 again",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
}

// The markdown is the comment a pull request gets, and the same three views decide its shape. A
// pipeline template sets one and every comment on that project follows it.
func TestTheCommentTakesTheSameViews(t *testing.T) {
	r := Result{
		New: []sarif.Result{{
			RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy", Control: "sca",
			Package: &sarif.Package{Name: "urllib3", Version: "2.0.7", FixedVersion: "2.6.0"},
		}},
		Gate: Gate{FailOnPriority: "P1"},
	}
	r.Tripped = r.GateNew("", "P1")

	var table, actions strings.Builder
	if err := Render(&table, "markdown", r, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Render(&actions, "markdown", r, Options{View: ViewActions}); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(table.String(), "| Change | Priority |") {
		t.Errorf("the default comment is a row per finding:\n%s", table.String())
	}
	got := actions.String()
	if !strings.Contains(got, "### What to do") || !strings.Contains(got, "Upgrade urllib3 2.0.7") {
		t.Errorf("the actions comment does not group the change:\n%s", got)
	}
	// The verdict and the rule behind it travel with both, because a comment is read by somebody
	// who was not there when it ran.
	for _, shape := range []string{table.String(), got} {
		if !strings.Contains(shape, "FAIL") || !strings.Contains(shape, "fails on any P1") {
			t.Errorf("a comment without its gate cannot be checked:\n%s", shape)
		}
	}
	// Marked, where the terminal is not. A comment has no ramp to find a count by.
	if !strings.Contains(got, "🔺") {
		t.Errorf("the comment's summary carries no mark:\n%s", got)
	}
}

// A comment for a change that introduced nothing still says what it compared and what it was
// measured against.
func TestTheCommentSaysWhenNothingChanged(t *testing.T) {
	r := Result{
		Unchanged: []sarif.Result{{RuleID: "CVE-1"}},
		Gate:      Gate{FailOnPriority: "P1"},
	}
	for _, view := range []View{ViewFindings, ViewActions} {
		var b strings.Builder
		if err := Render(&b, "markdown", r, Options{View: view}); err != nil {
			t.Fatal(err)
		}
		got := b.String()
		if !strings.Contains(got, "pass") || !strings.Contains(got, "Nothing changed") {
			t.Errorf("%s: a clean comment should read clean:\n%s", view, got)
		}
		if !strings.Contains(got, "fails on any P1") {
			t.Errorf("%s: the rule is missing from a passing comment:\n%s", view, got)
		}
	}
}

// Everything that changed is somebody else's problem to fix or nobody's: a diff of fixes alone has
// no work in it, and an actions listing has to say so rather than drawing an empty table.
func TestAnActionsListingWithNoWorkSaysSo(t *testing.T) {
	r := Result{Fixed: []sarif.Result{{RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1"}}}
	var b strings.Builder
	if err := Render(&b, "markdown", r, Options{View: ViewActions}); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); !strings.Contains(got, "none of it needs anybody") {
		t.Errorf("an empty work list should say why it is empty:\n%s", got)
	}
}

// The three names the flag accepts are the three the help text offers.
func TestViewsAreTheOnesTheFlagNames(t *testing.T) {
	want := []View{ViewActions, ViewCompact, ViewFindings}
	got := Views()
	if len(got) != len(want) {
		t.Fatalf("Views() = %v, want one entry per view", got)
	}
	for i, v := range want {
		if got[i] != string(v) {
			t.Errorf("Views()[%d] = %q, want %q, sorted", i, got[i], v)
		}
	}
}
