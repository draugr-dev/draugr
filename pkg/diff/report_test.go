package diff

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// twoComponentsOneCVE is the case a pull-request comment on a monorepo actually produces: the
// same dependency reached from two services. The fingerprint separates them, so they are two
// findings — and without the component they are two rows identical in every visible column.
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
	if err := Render(&b, "markdown", twoComponentsOneCVE()); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if !strings.Contains(got, "| Priority | Severity | Rule | Tool | Component | Location |") {
		t.Errorf("missing the column:\n%s", got)
	}
	for _, want := range []string{"payments", "internal-tool"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q — the two rows are indistinguishable:\n%s", want, got)
		}
	}
}

func TestConsoleNamesTheComponent(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "console", twoComponentsOneCVE()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"payments", "internal-tool"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q:\n%s", want, b.String())
		}
	}
}

func TestNoComponentColumnWhenNobodyHasOne(t *testing.T) {
	// A single-component project would get a column repeating itself — the rule the scan report
	// already follows.
	r := Result{New: []sarif.Result{{RuleID: "x", Level: sarif.LevelError, Tool: "trivy"}}}
	var b bytes.Buffer
	if err := Render(&b, "markdown", r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Component") {
		t.Errorf("nothing to say:\n%s", b.String())
	}
}

func TestComponentColumnAppearsWhenOnlyFixedHasOne(t *testing.T) {
	// Both lists share one header decision, so the fixed list must be consulted too.
	r := Result{Fixed: []sarif.Result{
		{RuleID: "x", Level: sarif.LevelError, Tool: "trivy", Component: "web"},
	}}
	var b bytes.Buffer
	if err := Render(&b, "markdown", r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "| web |") {
		t.Errorf("a fixed finding's component should show:\n%s", b.String())
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
		if err := Render(&b, format, r); err != nil {
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

func TestDiffHeadlineNamesOnlyTheBandsPresent(t *testing.T) {
	// "0 critical, 0 high, 2 medium" makes a reader scan past two zeroes to find the number that
	// matters. A clean diff should also not read as a list of things that are fine.
	r := Result{New: []sarif.Result{
		{RuleID: "a", Level: sarif.LevelError, Score: 9.8, HasScore: true},
		{RuleID: "b", Level: sarif.LevelWarning},
	}}
	got := headline(r)
	if !strings.Contains(got, "1 critical") || !strings.Contains(got, "1 medium") {
		t.Errorf("headline = %q", got)
	}
	// Only the parenthesised bands — "0 fixed" and "0 unchanged" are counts, and a zero there
	// is the answer rather than noise.
	if bands := got[strings.Index(got, "(")+1 : strings.Index(got, ")")]; strings.Contains(bands, "0 ") {
		t.Errorf("headline names bands that did not occur: %q", got)
	}
	if clean := headline(Result{}); clean != "0 new, 0 fixed, 0 unchanged" {
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
	if err := Render(&buf, "sarif", r); err != nil {
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
	if err := Render(&buf, "markdown", r); err != nil {
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
// new findings actually cite — carrying the other few hundred would put the noise back.
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
	if err := Render(&buf, "sarif", r); err != nil {
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
