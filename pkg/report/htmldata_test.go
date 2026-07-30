package report

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"regexp"
	"strings"
	"testing"

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

// The report is often the only artifact that travels — someone who wants the findings in a
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

// The downloads and the whole table have to work with scripts disabled — this file gets emailed,
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

// Suppressed findings are the auditor's question — who accepted this, and why. A count alone
// does not answer it.
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
	if !strings.Contains(page, "Suppressed") {
		t.Error("no suppressed section")
	}
	if !strings.Contains(page, "Fixture key, never valid anywhere.") {
		t.Error("the justification is not shown")
	}
}
