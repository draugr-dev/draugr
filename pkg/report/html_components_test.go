package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// componentData is a run over two components, because one proves the loop runs and two prove the
// table does not collapse them. They differ in every column the table has: verdict, what the
// descriptor declared, how findings ranked, and whether anything went unscanned.
// Built on the golden run rather than from nothing, so the findings are ranked and the table
// renders the vocabulary a real report uses. A Data holding components that claim findings the run
// does not contain reads as unranked, and every band assertion below would pass on an empty cell.
func componentData() Data {
	d := goldenFullData()
	d.Scope = &Scope{SkippedComponents: []string{"batch"}}
	d.Components = []ComponentVerdict{
		{
			Name: "api", Verdict: norn.Fail,
			Exposure: "public", Criticality: "critical",
			Findings: 6, Priorities: [4]int{2, 3, 1, 0},
			Controls: []string{"sca", "secrets"},
		},
		{
			Name: "worker", Verdict: norn.Pass,
			Exposure: "internal", Criticality: "supporting",
			Findings: 2, Priorities: [4]int{0, 0, 1, 1},
			Unscanned: []engine.Unscanned{{Control: "images", Kind: "image", Target: "r/a:1"}},
			Declared:  map[string]int{"image": 3},
		},
	}
	d.UnattributedFindings = 4
	return d
}

func renderHTML(t *testing.T, d Data) string {
	t.Helper()
	var buf bytes.Buffer
	if err := (htmlReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestTheReportSaysWhichComponentIsFailing is the parity gap this closes. The console prints a
// component's verdict and the rendered report dropped it, so the copy somebody shares was the one
// that could not answer whose problem it is.
func TestTheReportSaysWhichComponentIsFailing(t *testing.T) {
	out := renderHTML(t, componentData())

	for _, want := range []string{
		`<summary id="components"`,
		`<a class="tab" href="#components">Components</a>`,
		`<th scope="row">api</th>`,
		`<th scope="row">worker</th>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the components table is missing %q", want)
		}
	}
	// Each component's own verdict, not the run's. A table that showed the run's verdict on every
	// row would be four copies of the header and would say nothing about whose problem it is.
	api := section(t, out, `<th scope="row">api</th>`, `<th scope="row">worker</th>`)
	if !strings.Contains(api, "FAIL") || strings.Contains(api, ">PASS<") {
		t.Errorf("the failing component is not marked failing:\n%s", api)
	}
	worker := section(t, out, `<th scope="row">worker</th>`, "</tbody>")
	if !strings.Contains(worker, ">PASS<") {
		t.Errorf("the passing component is not marked passing:\n%s", worker)
	}
}

// TestTheTableSaysWhatEachComponentWasDeclaredToBe: exposure and criticality are half of why two
// components holding the same finding rank differently, so a table without them shows a difference
// whose cause is off screen.
func TestTheTableSaysWhatEachComponentWasDeclaredToBe(t *testing.T) {
	out := renderHTML(t, componentData())
	for _, want := range []string{"public · critical", "internal · supporting"} {
		if !strings.Contains(out, want) {
			t.Errorf("the declared classification %q is missing", want)
		}
	}
}

// TestAComponentThatDeclaredNothingSaysSo. An empty cell reads as a rendering fault; the reader
// cannot tell it from a value that failed to print, and the fix is in their descriptor.
func TestAComponentThatDeclaredNothingSaysSo(t *testing.T) {
	d := componentData()
	d.Components[0].Exposure, d.Components[0].Criticality = "", ""
	if got := renderHTML(t, d); !strings.Contains(got, "not declared") {
		t.Error("a component with no exposure or criticality left the cell blank")
	}
}

// TestHalfAClassificationStillRenders covers the descriptor that declared one of the two. Joining
// with a separator unconditionally would print "public · " and read as a value that went missing.
func TestHalfAClassificationStillRenders(t *testing.T) {
	for _, c := range []struct{ exposure, criticality, want string }{
		{"public", "", "public"},
		{"", "critical", "critical"},
	} {
		if got := classification(c.exposure, c.criticality); got != c.want {
			t.Errorf("classification(%q, %q) = %q, want %q", c.exposure, c.criticality, got, c.want)
		}
	}
}

// TestAComponentNothingLookedAtIsNotAPass is the console's rule, held to here too. Its scans
// failed, so "no findings" is true only in the sense that none were possible, and a reader of the
// shared copy has no other way to find that out.
func TestAComponentNothingLookedAtIsNotAPass(t *testing.T) {
	d := componentData()
	d.Components[1].Findings, d.Components[1].Priorities = 0, [4]int{}

	row := section(t, renderHTML(t, d), `<th scope="row">worker</th>`, "</tbody>")
	if !strings.Contains(row, "ERROR") {
		t.Errorf("a component nothing was scanned for is not a pass:\n%s", row)
	}
	if strings.Contains(row, "no findings") {
		t.Errorf("a component nothing was scanned for claimed no findings:\n%s", row)
	}
}

// TestAPartlyScannedComponentReportsBothHalves. Findings worth acting on and a gap are two facts,
// and substituting one for the other loses whichever the reader needed.
func TestAPartlyScannedComponentReportsBothHalves(t *testing.T) {
	row := section(t, renderHTML(t, componentData()), `<th scope="row">worker</th>`, "</tbody>")
	if !strings.Contains(row, "1/3 images not scanned") {
		t.Errorf("the gap is missing:\n%s", row)
	}
	if !strings.Contains(row, "P3 1") {
		t.Errorf("the findings are missing:\n%s", row)
	}
}

// TestASkippedComponentIsListedRatherThanOmitted. An absent row renders identically to one that
// passed, and absence is exactly how a reader concludes there was nothing to find.
func TestASkippedComponentIsListedRatherThanOmitted(t *testing.T) {
	out := renderHTML(t, componentData())
	if !strings.Contains(out, `<th scope="row">batch</th>`) {
		t.Error("a component the scope left out is missing from the table")
	}
	row := section(t, out, `<th scope="row">batch</th>`, "</tbody>")
	if !strings.Contains(row, "not scanned") {
		t.Errorf("the skipped component does not say it was not scanned:\n%s", row)
	}
	if strings.Contains(row, "PASS") {
		t.Errorf("a component nobody scanned is reported as passing:\n%s", row)
	}
}

// TestFindingsTiedToNoComponentAreCounted. Project-wide controls produce them, and a breakdown that
// omits them makes the parts look like the whole.
//
// One sentence across all three formats. Each renderer wrote its own, and the one with room for a
// longer version used it, so the same fact reached a reader as three different claims and only the
// terse two were saying it in the product's own words.
func TestFindingsTiedToNoComponentAreCounted(t *testing.T) {
	const said = "not tied to a component (project-wide controls)"
	for _, r := range []Reporter{consoleReporter{}, markdownReporter{}, htmlReporter{}} {
		t.Run(r.Format(), func(t *testing.T) {
			var buf bytes.Buffer
			if err := r.Render(&buf, componentData()); err != nil {
				t.Fatal(err)
			}
			// Compared as the reader meets it. A sentence wrapped in the source is one line on
			// screen, in a terminal and in a browser alike, so a newline between two of its words
			// is not a difference in what anybody was told.
			out := strings.Join(strings.Fields(buf.String()), " ")
			if !strings.Contains(out, said) {
				t.Errorf("findings belonging to no component are not reported as %q", said)
			}
			if !strings.Contains(out, "4 findings") {
				t.Error("the count is missing")
			}
		})
	}
}

// TestARunWithNoComponentsShowsNoTable. One component is the common case and a table of one row is
// a heading over a fact the header already carries.
func TestARunWithNoComponentsShowsNoTable(t *testing.T) {
	out := renderHTML(t, Data{Release: saga.Release{Version: "1.0"}, Verdict: norn.Result{Verdict: norn.Pass}})
	if strings.Contains(out, `id="components"`) {
		t.Error("a run with no component breakdown still rendered the table")
	}
	if strings.Contains(out, `href="#components"`) {
		t.Error("the nav offers a section that is not on the page")
	}
}

// TestAnUnrankedRunCountsFindingsInsteadOfBands. Priority chips on a run that ranked nothing would
// be four zeros claiming every finding is a P4.
func TestAnUnrankedRunCountsFindingsInsteadOfBands(t *testing.T) {
	d := componentData()
	for name, control := range d.Run.Controls {
		for i := range control.Report.Results {
			control.Report.Results[i].Priority = ""
		}
		d.Run.Controls[name] = control
	}
	for i := range d.Components {
		d.Components[i].Priorities = [4]int{}
	}

	out := renderHTML(t, d)
	if strings.Contains(out, "P1 0") {
		t.Error("an unranked run showed empty priority chips")
	}
	if !strings.Contains(out, "6 findings") {
		t.Error("an unranked run did not fall back to a finding count")
	}
}

// TestTheStripDescribesOneComponentOnly. It carries that component's verdict, its failing controls
// and its gaps, and there is no such thing for two: a strip averaging them would be a number
// nothing holds. Which is why the markup exists per component and the script reveals one.
func TestTheStripDescribesOneComponentOnly(t *testing.T) {
	out := renderHTML(t, componentData())

	for _, want := range []string{`<div class="focus" data-m="api" hidden>`, `data-m="worker"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the strip for %q is missing", want)
		}
	}
	if strings.Contains(out, `data-m="batch"`) {
		t.Error("a component this run never scanned has a strip, which would show a verdict nobody reached")
	}
	// Hidden until the menus name one. Shipping it visible would put two components' strips above
	// an unfiltered list, each describing a part of it.
	if strings.Count(out, `class="focus" data-m=`) != strings.Count(out, `class="focus" data-m="api" hidden`)+
		strings.Count(out, `class="focus" data-m="worker" hidden`) {
		t.Error("a strip renders visible rather than hidden")
	}
	if !strings.Contains(out, "m.length === 1") {
		t.Error("the script does not restrict the strip to a single component")
	}
}

// TestTheStripNamesTheControlsThatFailed. Once somebody has narrowed to one component, which
// control it did not pass is the next question, and the table has no room for it.
func TestTheStripNamesTheControlsThatFailed(t *testing.T) {
	out := renderHTML(t, componentData())
	strip := section(t, out, `data-m="api"`, `data-m="worker"`)
	if !strings.Contains(strip, "failing sca, secrets") {
		t.Errorf("the strip does not name the failing controls:\n%s", strip)
	}
	clean := section(t, out, `data-m="worker"`, `<p class="state">`)
	if strings.Contains(clean, "failing") {
		t.Errorf("a component that passed every control is described as failing one:\n%s", clean)
	}
}

// TestTheStripDoesNotRestateItsOwnBands. The count is the sum of the chips beside it and the line
// under it already says how many the filter left, so on a ranked run it is the same number three
// times. On a run that ranked nothing there are no chips, and then it is the only quantity there.
func TestTheStripDoesNotRestateItsOwnBands(t *testing.T) {
	ranked := section(t, renderHTML(t, componentData()), `data-m="api"`, `data-m="worker"`)
	if strings.Contains(ranked, "6 findings") {
		t.Errorf("the strip repeats what its own chips add up to:\n%s", ranked)
	}

	d := componentData()
	for name, control := range d.Run.Controls {
		for i := range control.Report.Results {
			control.Report.Results[i].Priority = ""
		}
		d.Run.Controls[name] = control
	}
	unranked := section(t, renderHTML(t, d), `data-m="api"`, `data-m="worker"`)
	if !strings.Contains(unranked, "6 findings") {
		t.Errorf("a run with no bands left the strip with no quantity at all:\n%s", unranked)
	}
}

// section returns the markup between two landmarks, so an assertion about one row cannot be
// satisfied by a different row on the same page.
func section(t *testing.T, doc, from, to string) string {
	t.Helper()
	i := strings.Index(doc, from)
	if i < 0 {
		t.Fatalf("%q is not in the document", from)
	}
	rest := doc[i:]
	if j := strings.Index(rest, to); j > 0 {
		return rest[:j]
	}
	return rest
}

// A message too long for its row opens to the whole of it; one that fits stays a plain row. Two
// findings, because one proves the disclosure renders and two prove it is not applied to every row.
func TestAShortenedMessageOpensToTheWholeOfIt(t *testing.T) {
	long := "Content-Security-Policy blocks image from https://images.example-cdn.com, which this page " +
		"loads (https://images.example-cdn.com/hero.jpg). The browser refuses it. Add the origin to " +
		"default-src, or stop loading from it. <b>escaped</b>"
	d := Data{
		Run: engine.Result{Controls: map[string]plugin.ControlResult{"headers": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "headers/csp-blocks-image-origin", Level: sarif.LevelNote, Tool: "draugr-headers", Message: long},
			{RuleID: "headers/hsts-missing", Level: sarif.LevelWarning, Tool: "draugr-headers", Message: "Missing HSTS."},
		}}}}},
		Verdict: norn.Result{Verdict: norn.Fail},
	}
	out := renderHTML(t, d)

	if n := strings.Count(out, `<details class="more">`); n != 1 {
		t.Errorf("%d disclosures; want one, for the shortened message only", n)
	}
	if !strings.Contains(out, `<p class="full">`+strings.ReplaceAll(strings.ReplaceAll(long, "<", "&lt;"), ">", "&gt;")+`</p>`) {
		t.Error("the disclosure does not carry the whole message, escaped")
	}
	if !strings.Contains(out, `<div class="rule"><span class="id">headers/hsts-missing</span><span class="said"><span class="faint"> · </span>Missing HSTS.</span></div>`) {
		t.Error("a message that fits is not a plain row")
	}
}
