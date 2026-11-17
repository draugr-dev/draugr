package diff

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fixlist "github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// rebanded is one repository whose api component declared more exposure between the scans and whose
// worker declared less: one finding raised, one lowered, one left at its band.
func rebanded() (base, head sarif.Report) {
	const repo = "https://github.com/acme/shop"
	up, down, same := finding("CVE-1", "api/go.mod", 3), finding("CVE-2", "worker/go.mod", 5), finding("CVE-3", "api/go.mod", 3)
	base = sarif.Report{Results: []sarif.Result{in(up, "api", repo, "P4"), in(down, "worker", repo, "P1"), in(same, "api", repo, "P2")}}
	head = sarif.Report{Results: []sarif.Result{in(up, "api", repo, "P1"), in(down, "worker", repo, "P3"), in(same, "api", repo, "P2")}}
	return base, head
}

// A finding counting in both scans at another band is reranked, with the band it had, and is not
// also counted as unchanged.
func TestABandChangeIsRerankedRatherThanUnchanged(t *testing.T) {
	got := Compare(rebanded())
	if len(got.New)+len(got.Fixed)+len(got.Moved)+len(got.Accepted)+len(got.Unaccepted) != 0 {
		t.Fatalf("new %d, fixed %d, moved %d, accepted %d, unaccepted %d; want none",
			len(got.New), len(got.Fixed), len(got.Moved), len(got.Accepted), len(got.Unaccepted))
	}
	if len(got.Unchanged) != 1 || got.Unchanged[0].RuleID != "CVE-3" {
		t.Errorf("unchanged = %+v, want CVE-3 alone", got.Unchanged)
	}
	if len(got.Reranked) != 2 {
		t.Fatalf("reranked = %+v, want 2", got.Reranked)
	}
	// Raised first, whatever the head's bands.
	if r := got.Reranked[0]; r.RuleID != "CVE-1" || r.From != "P4" || r.Priority != "P1" || !r.Raised() {
		t.Errorf("first reranked = %s %s → %s raised %v, want CVE-1 P4 → P1 raised", r.RuleID, r.From, r.Priority, r.Raised())
	}
	if r := got.Reranked[1]; r.RuleID != "CVE-2" || r.From != "P1" || r.Priority != "P3" || r.Raised() {
		t.Errorf("second reranked = %s %s → %s raised %v, want CVE-2 P1 → P3 lowered", r.RuleID, r.From, r.Priority, r.Raised())
	}
}

// The gate reads new findings alone. A finding raised to P1 was already there, so a gate on new P1
// findings passes it, as it passes a moved one.
func TestARaisedFindingDoesNotTripTheGate(t *testing.T) {
	got := Compare(rebanded())
	if tripped := got.GateNew(sarif.SeverityLow, "P4"); len(tripped) != 0 {
		t.Errorf("a reranked finding tripped the gate: %+v", tripped)
	}
}

// A finding that changed component and band is moved, and only moved: the move is why the band
// changed, and the strips add up to the head scan only if each finding is in one of them.
func TestAMoveThatChangedBandIsMovedAlone(t *testing.T) {
	f := finding("CVE-1", "go.mod", 3)
	got := Compare(
		sarif.Report{Results: []sarif.Result{in(f, "shop", "repo", "P1")}},
		sarif.Report{Results: []sarif.Result{in(f, "checkout", "repo", "P3")}},
	)
	if len(got.Moved) != 1 || len(got.Reranked) != 0 || len(got.Unchanged) != 0 {
		t.Errorf("moved %d, reranked %d, unchanged %d; want 1, 0, 0", len(got.Moved), len(got.Reranked), len(got.Unchanged))
	}
}

// A finding excused in both scans is still accepted whatever its band did, because nobody works
// from it.
func TestAnExcusedFindingThatChangedBandIsStillAccepted(t *testing.T) {
	f := finding("CVE-1", "go.mod", 3)
	got := Compare(
		sarif.Report{Results: []sarif.Result{suppressed(in(f, "app", "repo", "P1"))}},
		sarif.Report{Results: []sarif.Result{suppressed(in(f, "app", "repo", "P4"))}},
	)
	if len(got.Reranked) != 0 || len(got.Unchanged) != 1 {
		t.Errorf("reranked %d, unchanged %d; want 0, 1", len(got.Reranked), len(got.Unchanged))
	}
}

// --min-priority narrows new findings only, as its help says, so a reranked one below the band
// stays listed.
func TestNarrowingNewLeavesRerankedAlone(t *testing.T) {
	got := Compare(rebanded()).NarrowNew("P1")
	if len(got.Reranked) != 2 {
		t.Errorf("reranked after NarrowNew = %d, want 2", len(got.Reranked))
	}
}

// Counted drops a second scanner's copy from Reranked, as it does from every other state.
func TestCountedDropsACopyFromReranked(t *testing.T) {
	copyOf := finding("CVE-1", "go.mod", 3)
	copyOf.Correlation = &sarif.Correlation{CountedUnder: "trivy"}
	r := Result{Reranked: []Rerank{{Result: finding("CVE-1", "go.mod", 3), From: "P2"}, {Result: copyOf, From: "P2"}}}
	if got := r.Counted().Reranked; len(got) != 1 || got[0].Correlated() {
		t.Errorf("reranked after Counted = %+v, want the counted finding alone", got)
	}
}

// The console counts the reranked findings in the headline and by direction, lists each with both
// bands, raised first, and does not say nothing changed.
func TestTheConsoleListsRerankedFindings(t *testing.T) {
	r := Compare(rebanded())
	r.Reranked[0].Message = "a template injection in the router"
	got := renderAs(t, "console", r, Options{})
	for _, want := range []string{
		"2 reranked (1 raised, 1 lowered)  1 unchanged", "RERANKED  2 · 1 raised, 1 lowered", "Nothing is new or fixed.",
		"a template injection in the router",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	if !lineHas(got, "reranked", "1 P1", "0 P2", "1 P3") || !lineHas(got, "unchanged", "0 P1", "1 P2") {
		t.Errorf("the strips should count head's bands, each finding once:\n%s", got)
	}
	if !lineHas(got, "P4 → P1", "CVE-1", "api", "api/go.mod:3") || !lineHas(got, "P1 → P3", "CVE-2", "worker") {
		t.Errorf("a row should carry both bands and the component:\n%s", got)
	}
	if strings.Index(got, "CVE-1") > strings.Index(got, "CVE-2") {
		t.Errorf("want the raised finding first:\n%s", got)
	}
	if strings.Contains(got, "Nothing changed") {
		t.Errorf("said nothing changed beside two reranked findings:\n%s", got)
	}
	compact := renderAs(t, "console", r, Options{View: ViewCompact})
	if strings.Contains(compact, "a template injection in the router") {
		t.Errorf("the compact view should drop the sentence:\n%s", compact)
	}
}

// A direction that did not happen is not named.
func TestOnlyTheDirectionsThatHappenedAreNamed(t *testing.T) {
	r := Compare(rebanded())
	r.Reranked = r.Reranked[1:]
	if got := renderAs(t, "console", r, Options{}); !strings.Contains(got, "RERANKED  1 · 1 lowered\n") {
		t.Errorf("want the lowered count alone:\n%s", got)
	}
}

// --top caps the reranked rows, says what it held back and offers the rest, in both formats.
func TestTopCapsTheRerankedFindings(t *testing.T) {
	r := Compare(rebanded())
	console := renderAs(t, "console", r, Options{Top: 1})
	for _, want := range []string{"RERANKED  top 1 of 2 · 1 raised, 1 lowered", "… and 1 not listed.", "--top 0"} {
		if !strings.Contains(console, want) {
			t.Errorf("console: missing %q:\n%s", want, console)
		}
	}
	if strings.Contains(console, "CVE-2") {
		t.Errorf("console: --top 1 listed the second finding:\n%s", console)
	}
	md := renderAs(t, "markdown", r, Options{Top: 1})
	if !strings.Contains(md, "### Reranked · top 1 of 2 · 1 raised, 1 lowered") || !strings.Contains(md, "_…and 1 not listed._") {
		t.Errorf("markdown: a capped listing should say what it held back:\n%s", md)
	}
}

// The comment carries the count, the strip and a table with both bands, in either view.
func TestTheCommentListsRerankedFindings(t *testing.T) {
	r := Compare(rebanded())
	r.Rules = map[string]sarif.Rule{"CVE-1": {HelpURI: "https://avd.example/cve-1"}}
	for _, view := range []View{ViewFindings, ViewActions} {
		got := renderAs(t, "markdown", r, Options{View: view})
		for _, want := range []string{
			"↕️ 2 reranked (1 raised, 1 lowered)", "_reranked_ · **1 P1** · 0 P2 · **1 P3** · 0 P4", "Nothing is new or fixed.",
			"### Reranked · 2 · 1 raised, 1 lowered",
			"| P4 → P1 | high | [`CVE-1`](https://avd.example/cve-1) | trivy | api | api/go.mod:3 |",
			"| P1 → P3 | high | [`CVE-2`](https://nvd.nist.gov/vuln/detail/CVE-2) | trivy | worker | worker/go.mod:5 |",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: missing %q:\n%s", view, want, got)
			}
		}
	}
}

// One component's rows leave the Component column out, as the changed table does.
func TestOneComponentsRerankedRowsNameNoComponent(t *testing.T) {
	r := Compare(rebanded())
	r.Reranked = r.Reranked[:1]
	if got := renderAs(t, "markdown", r, Options{}); !strings.Contains(got, "| Priority | Severity | Rule | Scanner | Location |\n") {
		t.Errorf("want no Component column:\n%s", got)
	}
}

// JSON lists each reranked finding with the band it had and its direction, and the summary counts
// them apart from unchanged.
func TestJSONCarriesEachRerankedFinding(t *testing.T) {
	var got struct {
		Summary struct {
			Reranked, Raised, Lowered, Unchanged int
		} `json:"summary"`
		Reranked []struct {
			Finding      sarif.Result `json:"finding"`
			FromPriority string       `json:"fromPriority"`
			Direction    string       `json:"direction"`
		} `json:"reranked"`
	}
	out := renderAs(t, "json", Compare(rebanded()), Options{})
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if s := got.Summary; s.Reranked != 2 || s.Raised != 1 || s.Lowered != 1 || s.Unchanged != 1 {
		t.Errorf("summary = %+v, want 2 reranked (1 raised, 1 lowered) and 1 unchanged", s)
	}
	if len(got.Reranked) != 2 || got.Reranked[0].FromPriority != "P4" || got.Reranked[0].Finding.Priority != "P1" ||
		got.Reranked[0].Direction != "raised" || got.Reranked[1].Direction != "lowered" {
		t.Errorf("reranked = %+v, want CVE-1 P4 → P1 raised, then the lowered one", got.Reranked)
	}
}

// A code-scanning upload carries new findings only, so a reranked one annotates nobody.
func TestSARIFLeavesRerankedOut(t *testing.T) {
	if got := renderAs(t, "sarif", Compare(rebanded()), Options{}); strings.Contains(got, "CVE-1") {
		t.Errorf("a reranked finding reached the SARIF upload:\n%s", got)
	}
}

// A scan judged on its change draws the reranked findings too, and hands them on as their own
// state with the band each had.
func TestAScansChangeCarriesRerankedFindings(t *testing.T) {
	v := ScanView{Result: Compare(rebanded())}
	states := v.States()
	if len(states.Reranked) != 2 || len(states.RerankedFrom) != 2 || states.RerankedFrom[0] != "P4" || len(states.Unchanged) != 1 {
		t.Errorf("states = reranked %d from %v, unchanged %d; want 2 from [P4 P1], 1", len(states.Reranked),
			states.RerankedFrom, len(states.Unchanged))
	}
	if !states.Changed() {
		t.Error("a change that reranked findings reports nothing changed")
	}
	var b bytes.Buffer
	if !v.WriteListing(&b, fixlist.View(ViewFindings), 0) || !strings.Contains(b.String(), "RERANKED") {
		t.Errorf("the listing should draw the reranked findings:\n%s", b.String())
	}
	var strips bytes.Buffer
	v.WriteStrips(&strips, "whole run", [4]int{1, 1, 1, 0})
	if !lineHas(strips.String(), "reranked", "1 P1", "0 P2", "1 P3") {
		t.Errorf("the strips should carry a reranked one:\n%s", strips.String())
	}
}

// Two scans of draugr-demo, the first with no exposure or criticality declared and the second with
// them declared, trimmed to a few of the worker's and the platform's findings and one in api whose
// band stayed. Every finding is in both scans, and declaring the context lowered five of them.
func TestDeclaringContextReportsTheFindingsItReranked(t *testing.T) {
	load := func(name string) sarif.Report {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("testdata", "declared-context", name)) // #nosec G304 -- a fixture this test names
		if err != nil {
			t.Fatal(err)
		}
		rep, err := sarif.FromSARIF(data)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	r := Compare(load("before.sarif"), load("after.sarif"))
	bands := map[string]string{}
	for _, rr := range r.Reranked {
		bands[rr.Component+" "+rr.RuleID] = rerankBand(rr)
	}
	want := map[string]string{
		"worker CVE-2026-4800":  "P1 → P2",
		"worker CVE-2020-28500": "P2 → P4",
		"worker javascript.lang.security.audit.dangerous-spawn-shell.dangerous-spawn-shell": "P2 → P4",
		"platform KSV-0014": "P1 → P3",
		"platform KSV-0110": "P3 → P4",
	}
	if len(bands) != len(want) {
		t.Errorf("reranked = %v, want %v", bands, want)
	}
	for k, v := range want {
		if bands[k] != v {
			t.Errorf("%s: %q, want %q", k, bands[k], v)
		}
	}
	// The api component shares the platform's file and rule and declared nothing new, so its copy
	// stays unchanged.
	if len(r.Unchanged) != 2 || len(r.New)+len(r.Fixed)+len(r.Moved) != 0 {
		t.Errorf("unchanged %d, new %d, fixed %d, moved %d; want 2, 0, 0, 0", len(r.Unchanged), len(r.New), len(r.Fixed), len(r.Moved))
	}
	got := renderAs(t, "console", r, Options{})
	if strings.Contains(got, "Nothing changed") || !strings.Contains(got, "5 reranked (5 lowered)  2 unchanged") ||
		!strings.Contains(got, "RERANKED  5 · 5 lowered") || !strings.Contains(got, "Nothing is new or fixed. Only priorities changed.") {
		t.Errorf("the diff should report the five reranked findings:\n%s", got)
	}
}
