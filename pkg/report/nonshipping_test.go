package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// nonShippingData is a run over two components in two repositories. Each holds a P1 under a test or
// example directory and a P3 in shipped code, and web holds one more test finding a setting set aside.
func nonShippingData() Data {
	at := func(control, component, repo, uri, prio, mark string) sarif.Result {
		return sarif.Result{Tool: "trivy", RuleID: "DS-0002", Level: sarif.LevelError, Message: "Image user should not be 'root'",
			Control: control, Component: component, Repository: repo, Priority: prio,
			Location: sarif.Location{URI: uri, StartLine: 1}, NonShipping: mark}
	}
	setAside := at("iac", "web", "https://example.test/web.git", "tests/b/Dockerfile", "P1", "test")
	setAside.Suppression = &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting,
		Justification: sarif.JustificationNonShipping, Source: `components["web"].controls.iac.nonShippingPaths`}
	iac := []sarif.Result{
		at("iac", "api", "https://example.test/api.git", "tests/Dockerfile", "P1", "test"),
		at("iac", "api", "https://example.test/api.git", "Dockerfile", "P3", ""),
		at("iac", "web", "https://example.test/web.git", "deploy/Dockerfile", "P3", ""),
		setAside,
	}
	sast := []sarif.Result{
		at("sast", "web", "https://example.test/web.git", "examples/app.js", "P1", "example"),
	}
	return Data{Run: engine.Result{NonShipping: 1, Controls: map[string]plugin.ControlResult{
		"iac":  {Report: sarif.Report{Results: iac}},
		"sast": {Report: sarif.Report{Results: sast}},
	}}}
}

// Every finding in shipped code is listed before any under docs, examples or tests, whatever its
// band, and the marked ones keep their bands among themselves.
func TestShippedCodeIsListedFirst(t *testing.T) {
	s := summarize(nonShippingData())
	var got []string
	for _, f := range s.findings {
		got = append(got, f.priority+" "+f.location)
	}
	want := []string{"P3 Dockerfile:1", "P3 deploy/Dockerfile:1", "P1 tests/Dockerfile:1", "P1 examples/app.js:1"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("order %v, want %v", got, want)
	}
	if s.nonShipping != 2 {
		t.Errorf("nonShipping = %d, want 2: the set-aside one is not counted", s.nonShipping)
	}
	if s.p1 != 2 || s.p3 != 2 {
		t.Errorf("bands P1 %d P3 %d, want 2 and 2: a marked finding still counts in its band", s.p1, s.p3)
	}
}

// The console states how many counted findings sit under docs, examples or tests beside the bands,
// says the list puts shipped code first, labels each marked finding beside its location in both
// views, and lists the set-aside one as a setting row.
func TestTheConsoleCountsAndLabelsNonShippingFindings(t *testing.T) {
	d := nonShippingData()
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Logf("rendered:\n%s", out)
	for _, want := range []string{
		" 2 P1 0 P2 2 P3 0 P4  2 findings in docs, examples or tests\n",
		"all 4, shipped code first, by priority",
		"      tests/Dockerfile:1 · test\n",
		"      examples/app.js:1 · example\n",
		"      Dockerfile:1\n",
		`components["web"].controls.iac.nonShippingPaths: suppress`,
		"1 finding suppressed · in docs, examples or tests",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("console output lacks %q", want)
		}
	}
	if strings.Index(out, "deploy/Dockerfile:1") > strings.Index(out, "examples/app.js:1") {
		t.Error("a marked finding is listed before one in shipped code")
	}

	d.View = ViewCompact
	buf.Reset()
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "tests/Dockerfile:1 · test") ||
		!strings.Contains(out, "examples/app.js:1 · example") || strings.Contains(out, "deploy/Dockerfile:1 ·") {
		t.Errorf("compact view does not label exactly the marked findings:\n%s", out)
	}
}

// With nothing marked the console says nothing about it and the heading keeps its order.
func TestTheConsoleIsSilentWithNothingMarked(t *testing.T) {
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{"iac": {Report: sarif.Report{Results: []sarif.Result{
		{Tool: "trivy", RuleID: "DS-0002", Level: sarif.LevelError, Priority: "P1", Location: sarif.Location{URI: "Dockerfile"}},
		{Tool: "trivy", RuleID: "DS-0001", Level: sarif.LevelError, Priority: "P2", Location: sarif.Location{URI: "app/Dockerfile"}},
	}}}}}}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "docs, examples or tests") || strings.Contains(out, "shipped code first") {
		t.Errorf("an unmarked run mentions the mark:\n%s", out)
	}
}

// Where every finding is marked the list is in band order again, and the heading says only that.
func TestTheHeadingKeepsPriorityWhereEveryFindingIsMarked(t *testing.T) {
	s := summary{nonShipping: 2, findings: make([]finding, 2)}
	if got := fixFirstHeading(tui.Plain(), s, 2, 2); strings.Contains(got, "shipped code first") {
		t.Errorf("heading %q claims an order nothing in the list follows", got)
	}
	s.nonShipping = 1
	if got := fixFirstHeading(tui.Plain(), s, 1, 2); !strings.Contains(got, "top 1 of 2, shipped code first, by priority") {
		t.Errorf("heading %q", got)
	}
	if got := fixFirstHeading(tui.Plain(), summary{nonShipping: 1, findings: make([]finding, 1), hidden: 1}, 1, 1); !strings.Contains(got, "shipped code first") {
		t.Errorf("heading %q, want the order named where a lower band holds the shipped finding", got)
	}
}

// Markdown says the count under the bands and labels each marked location in the table.
func TestMarkdownCountsAndLabelsNonShippingFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := (markdownReporter{}).Render(&buf, nonShippingData()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"2 findings in docs, examples or tests, counted and listed after the rest.",
		" tests/Dockerfile:1 · test |",
		" examples/app.js:1 · example |",
		" Dockerfile:1 |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "deploy/Dockerfile:1") > strings.Index(out, "tests/Dockerfile:1 · test") {
		t.Error("markdown lists a marked finding before one in shipped code")
	}
}

// The HTML report says the count above the list, labels each marked row beside its location, and
// lists shipped code first.
func TestHTMLCountsAndLabelsNonShippingFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := (htmlReporter{}).Render(&buf, nonShippingData()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`<p class="note">2 findings in docs, examples or tests, counted and listed after the rest.</p>`,
		`tests/Dockerfile:1<span class="faint"> · </span>test<span class="faint"> · </span>`,
		`examples/app.js:1<span class="faint"> · </span>example<span class="faint"> · </span>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	if strings.Contains(out, `deploy/Dockerfile:1<span class="faint"> · </span>test`) {
		t.Error("HTML labels a finding in shipped code")
	}
	if i, j := strings.Index(out, `deploy/Dockerfile:1<span`), strings.Index(out, `tests/Dockerfile:1<span`); i < 0 || j < 0 || i > j {
		t.Errorf("HTML order: shipped at %d, marked at %d, want shipped first", i, j)
	}
}
