package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// decodeDataURI pulls a data: URI's payload back out of rendered HTML the way a browser would:
// unescape the attribute, then base64-decode.
func decodeDataURI(t *testing.T, page, filename string) string {
	t.Helper()
	re := regexp.MustCompile(`<a href="(data:[^"]+)" download="` + regexp.QuoteMeta(filename) + `"`)
	m := re.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no download link for %s", filename)
	}
	uri := html.UnescapeString(m[1])
	_, payload, ok := strings.Cut(uri, ";base64,")
	if !ok {
		t.Fatalf("%s link is not base64", filename)
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode %s: %v", filename, err)
	}
	return string(raw)
}

// The report is often the only artifact that travels. Someone who wants the findings in a
// tracker or a spreadsheet should not have to go back and ask for the files.
func TestHTMLEmbedsUsableSARIF(t *testing.T) {
	var b strings.Builder
	if err := (htmlReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(decodeDataURI(t, b.String(), "results.sarif")), &doc); err != nil {
		t.Fatalf("embedded SARIF is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("embedded SARIF version = %v, want 2.1.0", doc["version"])
	}
}

func TestHTMLEmbedsTSVWithEveryFinding(t *testing.T) {
	var b strings.Builder
	if err := (htmlReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	tsv := decodeDataURI(t, b.String(), "findings.tsv")
	lines := strings.Split(strings.TrimRight(tsv, "\n"), "\n")
	if got := strings.Split(lines[0], "\t"); len(got) != len(tsvColumns) {
		t.Errorf("header has %d columns, want %d", len(got), len(tsvColumns))
	}
	if len(lines) != 4 { // sampleData has three findings
		t.Errorf("want 1 header + 3 findings, got %d lines:\n%s", len(lines), tsv)
	}
}

// A message containing a tab or newline would silently shift every later column, which a reader
// only notices as data in the wrong place.
func TestTSVNeutralisesFieldSeparators(t *testing.T) {
	d := sampleData()
	d.Run.Controls["images"].Report.Results[0].Message = "has\ta tab\nand a newline"
	var b strings.Builder
	if err := (htmlReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(strings.TrimRight(decodeDataURI(t, b.String(), "findings.tsv"), "\n"), "\n") {
		if n := len(strings.Split(line, "\t")); n != len(tsvColumns) {
			t.Errorf("line %d has %d fields, want %d", i, n, len(tsvColumns))
		}
	}
}

// The downloads and the whole table have to work with scripts disabled. This file gets emailed,
// opened from a build artifact, and read in viewers that strip scripts. The script only reveals
// the toolbar, which starts hidden precisely so a reader without it sees no dead controls.
func TestHTMLIsUsableWithoutJavaScript(t *testing.T) {
	var b strings.Builder
	if err := (htmlReporter{}).Render(&b, sampleData()); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	if !strings.Contains(page, `id="tools" hidden`) {
		t.Error("the filter toolbar should start hidden, so it is invisible without the script that drives it")
	}
	for _, want := range []string{`download="results.sarif"`, `download="findings.tsv"`, "CVE-1"} {
		if !strings.Contains(page, want) {
			t.Errorf("%q should render without any script running", want)
		}
	}
}

// Suppressed findings are the auditor's question, who accepted this, and why. A count alone does
// not answer it.
func TestHTMLListsSuppressedFindingsWithTheirReason(t *testing.T) {
	d := sampleData()
	d.Run.Controls["images"].Report.Results[1].Suppression = &sarif.Suppression{
		Kind: "external", Justification: "Fixture key, never valid anywhere.",
	}
	var b strings.Builder
	if err := (htmlReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	if !strings.Contains(page, "Accepted") {
		t.Error("no accepted section")
	}
	if !strings.Contains(page, "Fixture key, never valid anywhere.") {
		t.Error("the justification is not shown")
	}
}

// The file reports were the one place a reader could not find out that a finding outranked its
// severity because a catalog says it is being exploited. Every surface names the signals now, and
// from the same summary, so three renderings of one run cannot disagree about what moved it.
func TestRenderedReportsNameWhatMovedTheRanking(t *testing.T) {
	d := Data{Run: engine.Result{
		Controls: map[string]plugin.ControlResult{"sca": {Report: sarif.Report{
			Tool: "trivy",
			Results: []sarif.Result{{
				RuleID: "CVE-2024-3094", Level: sarif.LevelError, Tool: "trivy", Priority: "P1",
				Escalation: &sarif.Escalation{Signal: "kev", From: "high", To: "critical"},
			}},
		}}},
	}}

	var md bytes.Buffer
	if err := (markdownReporter{}).Render(&md, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "### Signals") || !strings.Contains(md.String(), "KEV") {
		t.Errorf("markdown does not say what raised the finding:\n%s", md.String())
	}

	var page bytes.Buffer
	if err := (htmlReporter{}).Render(&page, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "Signals") || !strings.Contains(page.String(), "KEV") {
		t.Error("the html report does not say what raised the finding")
	}
}

// A count says how much was set aside. It cannot say what anybody thought was acceptable about it,
// though every suppressed finding carries the reason, and that is the question this format is for.
func TestRenderedReportsAccountForEachDecision(t *testing.T) {
	d := suppressedBy("a.reviewer", "")
	var md bytes.Buffer
	if err := (markdownReporter{}).Render(&md, d); err != nil {
		t.Fatal(err)
	}
	out := md.String()
	for _, want := range []string{"### Decisions", "a.reviewer", "**unattributed**", "never"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown is missing %q:\n%s", want, out)
		}
	}
	// And the count above it stops repeating the roll call, which was the same fact twice.
	if strings.Contains(out, "1 accepted by a.reviewer") {
		t.Errorf("the count still carries the attribution the table below it gives:\n%s", out)
	}
}

// A rule that matched nothing is invisible in a report read apart from the descriptor, which is
// how this format is always read.
func TestRenderedReportsNameARuleThatMatchedNothing(t *testing.T) {
	d := Data{Run: engine.Result{UnmatchedExclusions: []saga.ExcludeRule{{
		Paths: []string{"tests*"}, Reason: "test files that are not deployed",
	}}}}
	var md bytes.Buffer
	if err := (markdownReporter{}).Render(&md, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "### Unmatched") || !strings.Contains(md.String(), "tests*") {
		t.Errorf("markdown does not name the dead rule:\n%s", md.String())
	}
	var page bytes.Buffer
	if err := (htmlReporter{}).Render(&page, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "Unmatched") || !strings.Contains(page.String(), "tests*") {
		t.Error("the html report does not name the dead rule")
	}
}

// A verdict a reader cannot check is a claim. Both formats travel away from the machine that ran
// the scan, so the rule has to travel with them.
func TestRenderedReportsStateTheGate(t *testing.T) {
	d := Data{Gate: GateSettings{FailOnPriority: "P2"}}
	var md bytes.Buffer
	if err := (markdownReporter{}).Render(&md, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "fails on P2") {
		t.Errorf("markdown does not say what the verdict was measured against:\n%s", md.String())
	}
	var page bytes.Buffer
	if err := (htmlReporter{}).Render(&page, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "fails on P2") {
		t.Error("the html report does not say what the verdict was measured against")
	}
}

// A column that says the same thing on every row answers nothing and takes width from the ones
// that do, in the format that gets pasted into a pull request where width is scarcest.
func TestMarkdownDropsAComponentColumnThatRepeatsItself(t *testing.T) {
	one := []finding{{component: "api"}, {component: "api"}}
	if varies(one, func(f finding) string { return f.component }) {
		t.Error("one value across every row is not a column")
	}
	two := []finding{{component: "api"}, {component: "web"}}
	if !varies(two, func(f finding) string { return f.component }) {
		t.Error("two values is exactly when the column earns its width")
	}
}
