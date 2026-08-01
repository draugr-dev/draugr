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
