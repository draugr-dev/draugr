package diff

import (
	"bytes"
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
