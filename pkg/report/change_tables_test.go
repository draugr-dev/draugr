package report

import (
	"fmt"
	"html/template"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// judgedTablesData is judgedJUnitData with its two components declared, so the Change section has
// components to place the new findings in. The change adds to api alone, and web holds findings
// that were there at the base.
func judgedTablesData() Data {
	d := judgedJUnitData()
	d.Components = []ComponentVerdict{
		{Name: "api", Verdict: norn.Fail, Priorities: [4]int{2, 1, 1, 0}},
		{Name: "web", Verdict: norn.Fail, Priorities: [4]int{2, 1, 0, 0}},
	}
	return d
}

// The Change section counts what the change added and places it: by band over the change, then the
// controls and the components it landed in, each with the bands it added to and none it did not.
// A control or component the change added nothing to is not a row, however much it holds from before.
func TestTheChangeSectionCountsWhatTheChangeAddedWhereItLanded(t *testing.T) {
	c := changeViewFor(judgedTablesData(), true)
	if c == nil {
		t.Fatal("no Change section on a judged run")
	}
	if c.Base != "aaaa111, bbbb222" || c.Threshold != "P1" || !c.Fail {
		t.Errorf("base=%q threshold=%q fail=%v, want both revisions, P1 and a failure", c.Base, c.Threshold, c.Fail)
	}
	if want := "3 new findings, 2 of them at P1 or above."; c.Said != want {
		t.Errorf("said %q, want %q", c.Said, want)
	}
	if len(c.States) != 1 || c.States[0].Key != stateNew || c.States[0].N != 3 || !c.States[0].Listed {
		t.Fatalf("states = %+v, want new alone, 3 of them, a way into Findings", c.States)
	}
	if got := chipTexts(c.States[0].Bands); !reflect.DeepEqual(got, []string{"2 P1", "1 P3"}) {
		t.Errorf("bands = %v, want the bands the change added to and no empty one", got)
	}
	if !reflect.DeepEqual(c.Cols, []string{stateNew}) {
		t.Errorf("columns = %v, want new alone", c.Cols)
	}
	if len(c.Controls) != 1 || c.Controls[0].Name != "sca" || !c.Controls[0].Fail {
		t.Fatalf("controls = %+v, want sca alone, failing", c.Controls)
	}
	if got := chipTexts(c.Controls[0].Cells[0]); !reflect.DeepEqual(got, []string{"2 P1", "1 P3"}) {
		t.Errorf("sca's new bands = %v, want 2 P1 and 1 P3 with the empty bands left out", got)
	}
	if len(c.Components) != 1 || c.Components[0].Name != "api" || !c.Components[0].Fail {
		t.Errorf("components = %+v, want api alone, failing", c.Components)
	}
	if c.Caveats != "" {
		t.Errorf("caveats = %q on a run with none failing", c.Caveats)
	}
}

// chipTexts is what each chip says.
func chipTexts(chips []htmlChip) []string {
	out := make([]string, 0, len(chips))
	for _, c := range chips {
		out = append(out, c.Text)
	}
	return out
}

// A run with no gate on new findings has no Change section and no chip, in either report.
func TestAnUnjudgedRunHasNoChangeSection(t *testing.T) {
	d := judgedTablesData()
	d.Gate.New, d.Gate.FailOnNew = nil, ""
	if c := changeViewFor(d, true); c != nil {
		t.Errorf("Change section on an unjudged run: %+v", c)
	}
	html := renderWith(t, htmlReporter{}, d)
	for _, absent := range []string{`class="diff"`, `id="change"`, `href="#change"`} {
		if strings.Contains(html, absent) {
			t.Errorf("unjudged HTML report carries %s", absent)
		}
	}
	md := renderWith(t, markdownReporter{}, d)
	if strings.Contains(md, "diff report") || strings.Contains(md, "### Change") {
		t.Errorf("unjudged markdown report names a change:\n%s", md)
	}
}

// The verdict's sentence for each shape of change.
func TestTheChangeVerdictSaysHowManyMetTheGate(t *testing.T) {
	for _, tc := range []struct {
		n, tripped int
		want       string
	}{
		{0, 0, "Nothing new since abc1234."},
		{1, 0, "1 new finding, below P2."},
		{4, 0, "4 new findings, none at P2 or above."},
		{1, 1, "1 new finding, at P2 or above."},
		{3, 3, "3 new findings, every one at P2 or above."},
		{5, 2, "5 new findings, 2 of them at P2 or above."},
	} {
		if got := changeSaid(tc.n, tc.tripped, "P2", "abc1234"); got != tc.want {
			t.Errorf("changeSaid(%d, %d) = %q, want %q", tc.n, tc.tripped, got, tc.want)
		}
	}
}

// A change that added nothing passes and draws no bands or rows: there is nothing to place.
func TestAChangeThatAddedNothingPassesWithNoRows(t *testing.T) {
	d := judgedTablesData()
	d.Gate.New.Introduced, d.Gate.New.Tripped = nil, nil
	c := changeViewFor(d, true)
	if c.Fail || c.Said != "Nothing new since aaaa111, bbbb222." || c.States != nil || c.Controls != nil || c.Components != nil {
		t.Errorf("change = %+v, want a pass with nothing drawn", c)
	}
}

// On a run with no priorities, a row counts its new findings, since there are no bands to split
// them by.
func TestAnUnprioritizedChangeCountsFindings(t *testing.T) {
	c := changeViewFor(judgedTablesData(), false)
	if got := chipTexts(c.States[0].Bands); !reflect.DeepEqual(got, []string{"3"}) || c.States[0].Bands[0].Class != "plain" {
		t.Errorf("new = %v, want a plain count of 3 on an unprioritized run", got)
	}
	if got := chipTexts(c.Controls[0].Cells[0]); !reflect.DeepEqual(got, []string{"3"}) {
		t.Errorf("sca's cell = %v, want 3", got)
	}
}

// A caveat that fails the run is the run's second reason, said in the Change section beside the
// change's own verdict, which stays the change's alone.
func TestTheChangeSectionSaysACaveatFailsTheRunToo(t *testing.T) {
	d := failingCaveatData()
	d.Gate.FailOnNew = "P2"
	d.Gate.New = &skald.NewFindings{
		Base:       []sarif.RepositoryRef{{URL: "https://example.com/api.git", Revision: "3f2a9c1"}},
		Introduced: []sarif.Result{{RuleID: "CVE-1", Control: "sca", Priority: "P3"}},
	}
	c := changeViewFor(d, true)
	if c.Fail {
		t.Error("the change's verdict failed on a finding below the gate")
	}
	if c.Caveats != "2 caveats fail the run" || c.CaveatCount != 2 {
		t.Errorf("caveats = %q (%d), want 2 caveats fail the run", c.Caveats, c.CaveatCount)
	}
	// Whether the base had them is not known here, so neither report says the change added them.
	if html := renderWith(t, htmlReporter{}, d); !strings.Contains(html, "The run also fails on 2 caveats, which count whether or not <code>3f2a9c1</code> had them.") {
		t.Error("the HTML Change section does not say the caveats fail the run")
	}
	if md := renderWith(t, markdownReporter{}, d); !strings.Contains(md, "**FAIL** · The run also fails on 2 caveats, which count whether or not `3f2a9c1` had them, listed under Caveats.") {
		t.Errorf("the markdown Change section does not say the caveats fail the run:\n%s", md)
	}
	if note := judgedNote(d); !strings.HasSuffix(note, " · 2 caveats fail the run") {
		t.Errorf("judged note = %q, want the caveats beside the change", note)
	}
	d.AcceptedErrors = true
	if c := changeViewFor(d, true); c.Caveats != "" {
		t.Errorf("caveats = %q on a run that accepted its errors", c.Caveats)
	}
}

// The HTML report gives a run judged on its change a Change tab, keeps the whole
// run's counts in the header and the Controls and Components sections, and places the change in the
// Change tab.
func TestTheHTMLDiffReportHasAChipAndAChangeTab(t *testing.T) {
	html := renderWith(t, htmlReporter{}, judgedTablesData())
	for _, want := range []string{
		`<a class="tab err" href="#change">Change</a>`,
		`<summary id="change"><span class="sec">Change</span></summary>`,
		"3 new findings, 2 of them at P1 or above.",
		// The header counts the whole run: four P1 findings, though the change added two.
		`<span class="band b1">4 P1</span>`,
		// Controls still counts the whole run, images included, which the change added nothing to.
		`<span class="ctl-name">images</span>`,
		"Verdicts and counts of the whole run. What the change added is under",
		// What to do about the change, each a way to its own new findings, and one to all of them.
		`<a class="chg-go" href="#findings-h" data-state="new" data-a=`,
		`>2 new at P1</a>`,
		// The count of each state is a way to its findings.
		`data-state="new" data-title="new since aaaa111, bbbb222">3</a>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(html, "New since") || strings.Contains(html, "Counts are of findings new") {
		t.Error("a whole-run section is labeled as counting new findings")
	}
}

// The markdown puts the Change section first, under a title that is the verdict alone, and keeps its
// Controls and Components tables on the whole run.
func TestTheMarkdownDiffReportLeadsWithTheChange(t *testing.T) {
	md := renderWith(t, markdownReporter{}, judgedTablesData())
	// Nothing is added to the verdict line: the section heading names the base.
	if !strings.HasPrefix(md, "## Draugr · ❌ FAIL\n") {
		t.Errorf("title is not the verdict alone:\n%s", md)
	}
	change := strings.Index(md, "### Change since `aaaa111, bbbb222`")
	controls := strings.Index(md, "### Controls")
	if change < 0 || controls < 0 || change > controls {
		t.Fatalf("Change section at %d, Controls at %d, want the change first:\n%s", change, controls, md)
	}
	for _, want := range []string{
		"**FAIL** · 3 new findings, 2 of them at P1 or above. Fails on a finding new since `aaaa111, bbbb222` at P1 or above.",
		"| + new | 3 | 2 P1 · 1 P3 |",
		"[What each state means](https://draugr.dev/docs/latest/guides/pr-diff/)",
		"_Everything below is of the whole run._",
		"| Control | Gate | + new |\n|---|---|---|\n| sca | **FAIL** | 2 P1 · 1 P3 |\n",
		"| Component | Gate | + new |\n|---|---|---|\n| api | **FAIL** | 2 P1 · 1 P3 |\n",
		"| Control | Verdict | P1 | P2 | P3 | P4 |",
		"| images | **FAIL** | 1 | 0 | 0 | 0 |",
		"| Component | Exposure | Criticality | Verdict | P1 | P2 | P3 | P4 | Failing controls |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q:\n%s", want, md)
		}
	}
}

// On a judged run the findings the change introduced lead both lists, marked new, whatever their
// band, and the HTML offers a Change filter over them.
func TestNewFindingsLeadTheListsMarkedNew(t *testing.T) {
	d := judgedTablesData()
	md := renderWith(t, markdownReporter{}, d)
	rows := strings.Split(md[strings.Index(md, "| Change | Priority"):], "\n")
	for i, rule := range []string{"CVE-NEW-", "CVE-NEW-", "CVE-LOW"} {
		if row := rows[2+i]; !strings.HasPrefix(row, "| + new |") || !strings.Contains(row, rule) {
			t.Errorf("markdown row %d = %q, want a new finding, %s", i, row, rule)
		}
	}
	if row := rows[5]; !strings.HasPrefix(row, "|  |") {
		t.Errorf("markdown row 4 = %q, want a finding from before, unmarked", row)
	}

	html := renderWith(t, htmlReporter{}, d)
	first := strings.Index(html, `data-change="`)
	if first < 0 || !strings.HasPrefix(html[first:], `data-change="new"`) {
		t.Error("the first finding in the HTML list is not a new one")
	}
	if strings.Count(html, `data-change="new"`) != 3 {
		t.Errorf("%d findings marked new in the HTML, want 3", strings.Count(html, `data-change="new"`))
	}
	// The template escapes a plus from data, which a browser draws as the plus.
	if !strings.Contains(html, `<span class="moved up"><span class="g">&#43;</span>new</span>`) {
		t.Error("no new finding carries the + new mark")
	}
}

// The Change section's actions are the fix list's own rows, in both reports: the same titles, in
// the same order, with the same counts of new findings.
func TestTheChangeActionsAreTheFixListsRows(t *testing.T) {
	d := judgedTablesData()
	acts := changeActions(d, summarize(d))
	if len(acts) == 0 {
		t.Fatal("no actions for a change that added three findings")
	}
	total := 0
	for _, a := range acts {
		total += a.New
	}
	if total != 3 {
		t.Errorf("the actions clear %d new findings, want all 3", total)
	}
	md := renderWith(t, markdownReporter{}, d)
	html := renderWith(t, htmlReporter{}, d)
	at := -1
	for _, a := range acts {
		line := fmt.Sprintf("- **%s** %s · %d new at %s", a.Priority, a.Title, a.New, a.NewPriority)
		i := strings.Index(md, line)
		if i < at {
			t.Errorf("markdown lacks %q, or lists it out of order:\n%s", line, md)
		}
		at = i
		if !strings.Contains(html, fmt.Sprintf(`data-state="new" data-a="%s" data-title="%s">%d new at %s</a>`, template.HTMLEscapeString(a.Key), template.HTMLEscapeString(a.Title), a.New, a.NewPriority)) {
			t.Errorf("the HTML Change section lacks the action %q", a.Title)
		}
	}
}

// An action the change added one P3 to, beside a P1 that was already there, is P3 work as far as the
// change goes: the Change section draws it at the band of what was added, and after the P1 work.
func TestAChangeActionTakesTheBandOfWhatTheChangeAdded(t *testing.T) {
	d := judgedTablesData()
	sca := d.Run.Controls["sca"]
	sca.Report.Results = append(sca.Report.Results,
		depResult("api", junitAPI, "CVE-OLD-MINIMIST", "P1", 9.0, "minimist", "1.2.0", "1.2.6"))
	d.Run.Controls["sca"] = sca
	acts := changeActions(d, summarize(d))
	if len(acts) != 2 {
		t.Fatalf("%d actions, want lodash and minimist", len(acts))
	}
	if acts[0].Priority != "P1" || !strings.Contains(acts[0].Title, "lodash") {
		t.Errorf("first = %s %q, want the lodash upgrade at P1", acts[0].Priority, acts[0].Title)
	}
	// It keeps the fix list's own badge, so it reads alike on both tabs, and says the band of what the
	// change added beside its count.
	if acts[1].NewPriority != "P3" || acts[1].Priority != "P1" || acts[1].New != 1 || !strings.Contains(acts[1].Title, "minimist") {
		t.Errorf("second = %s %q (%d new at %s), want minimist, badge P1, its one new finding at P3",
			acts[1].Priority, acts[1].Title, acts[1].New, acts[1].NewPriority)
	}
}

// A change can touch many actions. The Change section shows the most urgent few and counts the rest,
// and how many touch a new and an unaccepted finding, which its links into the fix list say.
func TestTheChangeSectionShowsAFewActionsAndLeadsToTheRest(t *testing.T) {
	var acts []htmlAction
	for i := range 7 {
		a := htmlAction{Title: fmt.Sprintf("action %d", i), New: 1}
		if i >= 5 {
			a.New, a.Unaccepted = 0, 1
		}
		acts = append(acts, a)
	}
	c := &changeView{}
	c.capActions(acts)
	if len(c.Actions) != changeActionCap || c.ActionsMore != 2 || c.OnNew != 5 || c.OnUnaccepted != 2 {
		t.Errorf("shown %d, more %d, on new %d, on unaccepted %d; want 5, 2, 5, 2",
			len(c.Actions), c.ActionsMore, c.OnNew, c.OnUnaccepted)
	}
	var b strings.Builder
	c.Base = "abc1234"
	writeChangeSection(&b, c)
	if !strings.Contains(b.String(), "- _…and 2 more actions, in the HTML report's What to do_") {
		t.Errorf("markdown does not count the rest:\n%s", b.String())
	}
}
