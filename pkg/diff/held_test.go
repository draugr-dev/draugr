package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// matrixRank ranks a finding by the default matrices alone, which is what the scan's ranking comes to
// for a finding no floor, cap or raise touched.
func matrixRank(res sarif.Result, e saga.Exposure, c saga.Criticality) string {
	return string(prioritization.DefaultMatrices().Prioritize(e, c, res.RankedSeverity()))
}

// on is r reported on component, at the classification the head declared for it.
func on(r sarif.Result, component, exposure, criticality string) sarif.Result {
	r.Component, r.Exposure, r.Criticality = component, exposure, criticality
	return r
}

func comp(name, exposure, criticality string, controls, repos []string) engine.ComponentDeclaration {
	return engine.ComponentDeclaration{Name: name, Exposure: saga.Exposure(exposure),
		Criticality: saga.Criticality(criticality), Controls: controls, Repositories: repos}
}

// A new finding ranks by the more exposed and the more critical of the base's and the head's
// classifications: the base's component of the same name, a base component that declared a
// repository this one has newly taken, and a base component a finding moved from. Never lower than
// the head ranked it.
func TestANewFindingRanksByTheStricterClassification(t *testing.T) {
	high := res("trivy", "CVE-9", sarif.LevelError, "go.mod", 1, "P3") // high, as restricted and supporting rank it
	base := engine.Declarations{Components: []engine.ComponentDeclaration{
		comp("api", "public", "critical", []string{"sca"}, []string{"r/api"}),
		comp("docs", "restricted", "supporting", []string{"sca"}, []string{"r/mono"}),
		comp("site", "public", "important", []string{"sca"}, []string{"r/mono"}),
		comp("old", "authenticated", "critical", nil, nil),
	}}
	for _, tc := range []struct {
		name string
		head engine.ComponentDeclaration
		// moved is a finding the comparison saw move from a base component to the head one.
		moved string
		want  string
	}{
		{name: "same name lowered", head: comp("api", "restricted", "supporting", nil, []string{"r/api"}), want: "P1"},
		{name: "renamed, followed by its repository", head: comp("api-v2", "restricted", "supporting", nil, []string{"r/api"}), want: "P1"},
		{name: "a repository it shared at the base pulls in nothing", head: comp("docs", "restricted", "supporting", nil, []string{"r/mono"}), want: "P3"},
		{name: "a repository moved to it", head: comp("docs", "restricted", "supporting", nil, []string{"r/mono", "r/api"}), want: "P1"},
		{name: "followed by a moved finding", head: comp("renamed", "restricted", "supporting", nil, nil), moved: "old", want: "P1"},
		{name: "new component", head: comp("fresh", "restricted", "supporting", nil, nil), want: "P3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := on(high, tc.head.Name, string(tc.head.Exposure), string(tc.head.Criticality))
			r := Result{New: []sarif.Result{f}}
			if tc.moved != "" {
				was := on(res("trivy", "CVE-0", sarif.LevelNote, "x", 1, "P3"), tc.moved, "", "")
				r.Moved = []Move{{Result: on(was, tc.head.Name, "", ""), Was: was}}
			}
			head := engine.Declarations{Components: []engine.ComponentDeclaration{tc.head}}
			got := r.HoldToBase(base, head, true, matrixRank)
			if got.New[0].Priority != tc.want {
				t.Errorf("band = %s, want %s", got.New[0].Priority, tc.want)
			}
			if raised := len(got.Held.Raised) > 0; raised != (tc.want != "P3") {
				t.Errorf("raised = %v (%+v)", raised, got.Held.Raised)
			}
		})
	}

	// A head stricter than its base keeps its own band, and a ranker that would lower it is not heeded.
	r := Result{New: []sarif.Result{on(res("trivy", "CVE-9", sarif.LevelError, "go.mod", 1, "P1"), "api", "public", "critical")}}
	lower := func(sarif.Result, saga.Exposure, saga.Criticality) string { return "P4" }
	if got := r.HoldToBase(base, engine.Declarations{}, true, lower); got.New[0].Priority != "P1" || len(got.Held.Raised) != 0 {
		t.Errorf("a finding was lowered: %+v", got.New[0])
	}
}

// A control the base turned on is dropped where the head does not run it on what it covered: per
// repository, so one moved to another component or a component renamed keeps it, and per component
// where it declared none. The base's findings from a dropped control leave Fixed for Unscanned.
func TestAControlTheBaseRanIsDroppedWhereTheHeadDoesNot(t *testing.T) {
	base := engine.Declarations{
		Controls: []string{"secrets"},
		Components: []engine.ComponentDeclaration{
			comp("api", "", "", []string{"sast", "sca"}, []string{"r/api"}),
			comp("docs", "", "", []string{"sast"}, []string{"r/mono"}),
			comp("site", "", "", []string{"sast", "sca"}, []string{"r/mono"}),
			comp("img", "", "", []string{"images"}, nil),
		},
	}
	for _, tc := range []struct {
		name string
		head engine.Declarations
		want string
	}{
		{name: "nothing changed", head: base, want: ""},
		{name: "renamed and a repository moved", head: engine.Declarations{Controls: []string{"secrets"}, Components: []engine.ComponentDeclaration{
			comp("api-v2", "", "", []string{"sast", "sca"}, []string{"r/api"}),
			comp("all", "", "", []string{"sast", "sca"}, []string{"r/mono"}),
			comp("img", "", "", []string{"images"}, nil),
		}}, want: ""},
		{name: "off on one of two sharing a repository", head: engine.Declarations{Controls: []string{"secrets"}, Components: []engine.ComponentDeclaration{
			comp("api", "", "", []string{"sast", "sca"}, []string{"r/api"}),
			comp("docs", "", "", []string{"sast"}, []string{"r/mono"}),
			comp("site", "", "", []string{"sast"}, []string{"r/mono"}),
			comp("img", "", "", []string{"images"}, nil),
		}}, want: "sca on site"},
		{name: "a component removed and a project control off", head: engine.Declarations{Components: []engine.ComponentDeclaration{
			comp("api", "", "", []string{"sast", "sca"}, []string{"r/api"}),
			comp("docs", "", "", []string{"sast"}, []string{"r/mono"}),
			comp("site", "", "", []string{"sast", "sca"}, []string{"r/mono"}),
		}}, want: "secrets and images on img"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := droppedList(dropped(base, tc.head)); got != tc.want {
				t.Errorf("dropped = %q, want %q", got, tc.want)
			}
		})
	}

	fixed := on(res("trivy", "CVE-1", sarif.LevelError, "go.mod", 1, "P1"), "site", "", "")
	fixed.Control = "sca"
	stillFixed := on(res("semgrep", "rule", sarif.LevelError, "a.go", 1, "P2"), "site", "", "")
	stillFixed.Control = "sast"
	head := engine.Declarations{Controls: []string{"secrets"}, Components: []engine.ComponentDeclaration{
		comp("api", "", "", []string{"sast", "sca"}, []string{"r/api"}),
		comp("site", "", "", []string{"sast"}, []string{"r/mono"}),
		comp("docs", "", "", []string{"sast"}, []string{"r/mono"}),
		comp("img", "", "", []string{"images"}, nil),
	}}
	got := Result{Fixed: []sarif.Result{fixed, stillFixed}, Gate: Gate{FailOnPriority: "P1"}}.HoldToBase(base, head, true, matrixRank)
	if len(got.Fixed) != 1 || got.Fixed[0].RuleID != "rule" || len(got.Held.Unscanned) != 1 {
		t.Errorf("fixed = %+v, unscanned = %+v", got.Fixed, got.Held.Unscanned)
	}
	if v, failed := verdict(got); v != "FAIL" || !failed {
		t.Errorf("verdict = %q, %v with a control dropped", v, failed)
	}
	if want := "this change stops sca on site, which the base ran"; got.Held.DroppedSentence() != want {
		t.Errorf("sentence = %q", got.Held.DroppedSentence())
	}
}

// A finding the change excused with an exclusion of its own is listed as accepted and gated as new;
// one an exclusion the base had excused is accepted; and a finding that was counting at the base and
// is excused now was already there, so it is not the change's to gate.
func TestAChangeCannotAcceptWhatItAdds(t *testing.T) {
	baseRes := res("trivy", "CVE-OLD", sarif.LevelError, "go.mod", 1, "P1")
	head := sarif.Report{Results: []sarif.Result{
		suppressed(res("trivy", "CVE-OLD", sarif.LevelError, "go.mod", 1, "P1")),
		suppressed(res("trivy", "CVE-SELF", sarif.LevelError, "go.mod", 2, "P1")),
		suppressed(res("trivy", "CVE-KNOWN", sarif.LevelError, "go.mod", 3, "P1")),
	}}
	r := Compare(sarif.Report{Results: []sarif.Result{baseRes}}, head)
	base := engine.Declarations{Exclusions: []saga.ExcludeRule{{Rules: []string{"CVE-KNOWN"}}}}
	got := r.HoldToBase(base, engine.Declarations{}, true, matrixRank)
	if len(got.Accepted) != 3 {
		t.Errorf("accepted = %d, want all three listed", len(got.Accepted))
	}
	if len(got.Held.SelfAccepted) != 1 || got.Held.SelfAccepted[0].RuleID != "CVE-SELF" {
		t.Fatalf("self-accepted = %+v", got.Held.SelfAccepted)
	}
	if tripped := got.GateNew("", "P1"); len(tripped) != 1 || tripped[0].RuleID != "CVE-SELF" {
		t.Errorf("tripped = %+v", tripped)
	}

	// A supplier's statement or a setting is not a rule the change wrote in the descriptor.
	vex := suppressed(res("trivy", "CVE-VEX", sarif.LevelError, "go.mod", 4, "P1"))
	vex.Suppression.Origin = sarif.OriginVEX
	r = Compare(sarif.Report{}, sarif.Report{Results: []sarif.Result{vex}})
	if got := r.HoldToBase(engine.Declarations{}, engine.Declarations{}, true, matrixRank); len(got.Held.SelfAccepted) != 0 {
		t.Errorf("a VEX statement read as the change's own exclusion")
	}
}

// What the base held is said in every format, and a base that recorded nothing says so.
func TestWhatTheBaseHeldIsSaid(t *testing.T) {
	self := suppressed(on(res("trivy", "CVE-SELF", sarif.LevelError, "go.mod", 2, "P2"), "api", "restricted", "supporting"))
	low := on(res("trivy", "CVE-NEW", sarif.LevelError, "go.mod", 1, "P4"), "api", "restricted", "supporting")
	gone := on(res("trivy", "CVE-GONE", sarif.LevelError, "go.mod", 1, "P1"), "api", "", "")
	gone.Control = "sca"
	r := Compare(sarif.Report{Results: []sarif.Result{gone}}, sarif.Report{Results: []sarif.Result{low, self}})
	base := engine.Declarations{Components: []engine.ComponentDeclaration{
		comp("api", "public", "critical", []string{"sca", "sast"}, []string{"r/api"})}}
	head := engine.Declarations{Components: []engine.ComponentDeclaration{
		comp("api", "restricted", "supporting", []string{"sast"}, []string{"r/api"})}}
	r = r.HoldToBase(base, head, true, matrixRank)
	r.Gate = Gate{FailOnPriority: "P1"}
	r.Tripped = r.GateNew("", "P1")
	if len(r.Tripped) != 2 {
		t.Fatalf("tripped = %+v, want both new findings at P1", r.Tripped)
	}
	notes := []string{
		"The base ran sca on api and this change does not, so nothing it adds there was looked for, and 1 finding from the base reads as not scanned rather than fixed",
		"2 new findings rank by the base's exposure and criticality, which this change lowers, until it merges",
		"1 new finding is excused by an exclusion this change adds, and counts as new until it merges",
	}
	for _, format := range []string{"console", "markdown"} {
		var buf bytes.Buffer
		if err := Render(&buf, format, r, Options{}); err != nil {
			t.Fatal(err)
		}
		for _, n := range notes {
			if !strings.Contains(buf.String(), n) {
				t.Errorf("%s does not say %q:\n%s", format, n, buf.String())
			}
		}
	}
	var buf bytes.Buffer
	if err := Render(&buf, "json", r, Options{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		HeldToBase struct {
			Raised       []json.RawMessage `json:"raised"`
			Dropped      []jsonDropped     `json:"dropped"`
			Unscanned    []json.RawMessage `json:"unscanned"`
			SelfAccepted []json.RawMessage `json:"selfAccepted"`
		} `json:"heldToBase"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	h := doc.HeldToBase
	if len(h.Raised) != 2 || len(h.Dropped) != 1 || h.Dropped[0] != (jsonDropped{Component: "api", Control: "sca"}) ||
		len(h.Unscanned) != 1 || len(h.SelfAccepted) != 1 {
		t.Errorf("heldToBase = %+v", h)
	}

	unrecorded := Compare(sarif.Report{}, sarif.Report{}).HoldToBase(engine.Declarations{}, engine.Declarations{}, false, matrixRank)
	if notes := unrecorded.Held.Notes(); len(notes) != 1 || !strings.HasPrefix(notes[0], "The base report records no exposure") {
		t.Errorf("unrecorded notes = %q", notes)
	}
	if !strings.Contains(renderJSONString(t, unrecorded), `"unrecorded": true`) {
		t.Error("the JSON does not say the base recorded nothing")
	}
	if got := (Result{}).Held.Notes(); len(got) != 0 || heldJSON(Held{}) != nil {
		t.Errorf("a comparison the base decided nothing in says %q", got)
	}
}

func renderJSONString(t *testing.T, r Result) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, "json", r, Options{}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
