package prioritization

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The concept page prints both matrices and works examples through them by hand. A hand-worked
// band reads as correct to anybody who has not run the arithmetic, so these tests run it: the
// printed tables must be the shipped ones, and each example must land where they put it.
const conceptDoc = "../../docs/concepts/prioritization.md"

// section returns the text under a heading, up to the next heading of any level.
func section(t *testing.T, heading string) string {
	t.Helper()
	body, err := os.ReadFile(conceptDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(body)
	i := strings.Index(doc, "\n"+heading+"\n")
	if i < 0 {
		t.Fatalf("%s has no %q heading", conceptDoc, heading)
	}
	rest := doc[i+len(heading)+2:]
	if j := strings.Index(rest, "\n#"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// inlineTag matches an inline HTML tag, such as the spans that color a band or a severity.
var inlineTag = regexp.MustCompile(`<[^>]+>`)

// rows returns the cells of each body row of the first markdown table in text, with inline HTML
// tags, backticks and bold marks removed.
func rows(text string) [][]string {
	var out [][]string
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "|-") || strings.HasPrefix(line, "| -") {
			continue
		}
		var cells []string
		for c := range strings.SplitSeq(strings.Trim(line, "|"), "|") {
			c = inlineTag.ReplaceAllString(c, "")
			cells = append(cells, strings.Trim(strings.TrimSpace(c), "`*"))
		}
		out = append(out, cells)
	}
	if len(out) > 0 {
		out = out[1:] // the header
	}
	return out
}

func TestTheDocumentedContextTableIsTheShippedOne(t *testing.T) {
	m := DefaultMatrices()
	got := rows(section(t, "### Step 1, tier"))
	if len(got) != len(saga.Exposures) {
		t.Fatalf("step 1 table has %d rows, want one per exposure (%d)", len(got), len(saga.Exposures))
	}
	crit := []saga.Criticality{saga.CriticalityCritical, saga.CriticalityImportant, saga.CriticalitySupporting}
	for _, r := range got {
		for i, c := range crit {
			if want := m.ContextOf(saga.Exposure(r[0]), c); r[i+1] != string(want) {
				t.Errorf("step 1 says %s × %s is %s; the shipped table says %s", r[0], c, r[i+1], want)
			}
		}
	}
}

func TestTheDocumentedBandTableIsTheShippedOne(t *testing.T) {
	m := DefaultMatrices()
	got := rows(section(t, "### Step 2, band"))
	if len(got) != 4 {
		t.Fatalf("step 2 table has %d rows, want one per tier", len(got))
	}
	sev := []sarif.Severity{sarif.SeverityCritical, sarif.SeverityHigh, sarif.SeverityMedium, sarif.SeverityLow}
	for _, r := range got {
		for i, s := range sev {
			if want := m.PriorityOf(Context(r[0]), s); r[i+1] != string(want) {
				t.Errorf("step 2 says %s × %s is %s; the shipped table says %s", r[0], s, r[i+1], want)
			}
		}
	}
}

// The worked example's band cell carries the mark beside the band, `P1 ↑ KEV`, so the band is
// the cell's first field.
func TestTheLedgerExampleLandsWhereTheTablesPutIt(t *testing.T) {
	text := section(t, "### The ledger CVE")
	cls := regexp.MustCompile("classified `(\\w+)` /\\s*`(\\w+)`").FindStringSubmatch(text)
	if cls == nil {
		t.Fatal("the worked example no longer names the component's exposure and criticality as `x` / `y`")
	}
	exposure, criticality := saga.Exposure(cls[1]), saga.Criticality(cls[2])
	got := rows(text)
	if len(got) == 0 {
		t.Fatal("the worked example has no table")
	}
	m := DefaultMatrices()
	for _, r := range got {
		severity := sarif.Severity(strings.Fields(r[1])[0])
		band := strings.Fields(r[2])[0]
		if want := m.Prioritize(exposure, criticality, severity); band != string(want) {
			t.Errorf("worked example %q: %s on %s / %s is %s, not %s", r[0], severity, exposure, criticality, want, band)
		}
	}
}
