package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// stubChange stands in for pkg/diff's view of a change, which this package cannot import: it says
// what it was asked to draw.
type stubChange struct{ listed bool }

func (stubChange) WriteStrips(w io.Writer, label string, whole [4]int) {
	_, _ = fmt.Fprintf(w, " %s %v\n\n", label, whole)
}

func (s stubChange) WriteListing(w io.Writer, view View, top int) bool {
	if s.listed {
		_, _ = fmt.Fprintf(w, "LISTING %s top %d\n", view, top)
	}
	return s.listed
}

// judged is a run the gate on new findings judged, against a base that recorded no revision.
func judged(gate GateSettings) Data {
	gate.New = &skald.NewFindings{Introduced: []sarif.Result{{RuleID: "CVE-1", Priority: "P1"}}}
	if gate.FailOnNew == "" {
		gate.FailOnNew = "high"
	}
	gate.BasePath = "main/results.sarif"
	return Data{Project: "shop", Verdict: norn.Result{Verdict: norn.Fail}, Gate: gate, Change: stubChange{listed: true}}
}

// The rule a judged run's verdict came from is the gate on new findings, in every report that
// states one, and --no-gate still says the verdict decided nothing.
func TestAJudgedRunStatesTheGateOnNewFindings(t *testing.T) {
	for _, tc := range []struct {
		gate GateSettings
		want string
	}{
		{GateSettings{FailOnNewFrom: "--fail-on-new"},
			"Gate: fails on high severity among findings new since main/results.sarif · --fail-on-new"},
		{GateSettings{FailOnNew: "p2"}, "Gate: fails on P2 among findings new since main/results.sarif"},
		{GateSettings{Disabled: true}, "off (--no-gate) · this verdict does not decide the exit code"},
	} {
		if got := gateSentence(judged(tc.gate)); got != tc.want {
			t.Errorf("gate sentence = %q, want %q", got, tc.want)
		}
	}
}

// A judged run under --no-gate says its verdict does not decide the exit code, and the listing is
// capped at --top where it was given one.
func TestAJudgedRunUnderNoGateSaysTheVerdictDecidesNothing(t *testing.T) {
	d := judged(GateSettings{Disabled: true})
	d.TopN = 5
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"DRAUGR  FAIL  shop  change since main/results.sarif · 1 new · fails on high severity",
		"whole run [0 0 0 0]",
		"Gate off (--no-gate) · this verdict does not decide the exit code.",
		"LISTING  top 5",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("output does not say %q:\n%s", want, b.String())
		}
	}
}

// A change that introduced nothing lists nothing, so TRY offers no other view of a listing and no
// rule to explain, and keeps only what this run makes worth trying.
func TestAJudgedRunWithNothingListedOffersNoOtherView(t *testing.T) {
	d := judged(GateSettings{})
	d.Change = stubChange{}
	d.Run.Controls = map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
		Results: []sarif.Result{{RuleID: "CVE-1", Priority: "P1", Level: sarif.LevelError}},
	}}}
	d.Suggestions = []Suggestion{{What: "--cache-dir .draugr/cache", Why: "reuse what did not change"}}
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "--cache-dir .draugr/cache") {
		t.Errorf("the run's own suggestion is missing:\n%s", b.String())
	}
	for _, not := range []string{"--view compact", "--view actions", "draugr explain"} {
		if strings.Contains(b.String(), not) {
			t.Errorf("offers %q with nothing listed:\n%s", not, b.String())
		}
	}
}

// Without a view of the change the console has nothing to draw it with, and prints the scan's own
// layout rather than half of the change's.
func TestAJudgedRunWithNoViewPrintsTheScan(t *testing.T) {
	d := judged(GateSettings{})
	d.Change = nil
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "change since") {
		t.Errorf("printed the change with nothing to draw it:\n%s", b.String())
	}
}

func TestThresholdWordsSayTheGateAsTheReportDoes(t *testing.T) {
	for setting, want := range map[string]string{"P3": "P3", "p1": "P1", "high": "high severity"} {
		if got := ThresholdWords(setting); got != want {
			t.Errorf("ThresholdWords(%q) = %q, want %q", setting, got, want)
		}
	}
}

// A base is named by each revision it read, once, and by its file where it records none.
func TestBaseNameQuotesTheRevisionsItRead(t *testing.T) {
	two := []sarif.RepositoryRef{
		{URL: "https://github.com/acme/api", Revision: "4f2a9c1e0b3d"},
		{URL: "https://github.com/acme/api.git", Revision: "4f2a9c1e0b3d"},
		{URL: "https://github.com/acme/web", Revision: "9d8e7f6"},
		{URL: "https://github.com/acme/docs"},
	}
	if got := BaseName(two, "base.sarif"); got != "4f2a9c1, 9d8e7f6" {
		t.Errorf("BaseName = %q, want each revision once", got)
	}
	if got := BaseName(nil, "base.sarif"); got != "base.sarif" {
		t.Errorf("BaseName = %q, want the file for a base that records no revision", got)
	}
}

// An upgrade names a release only where the fix list would make it one action with one to name.
func TestUpgradeTargetIsTheFixListsOwn(t *testing.T) {
	pkg := func(name, fixed string) sarif.Result {
		return sarif.Result{Control: "sca", RuleID: "CVE-" + name, Priority: "P2", Level: sarif.LevelWarning,
			Location: sarif.Location{URI: "requirements.txt", StartLine: 1},
			Package:  &sarif.Package{Name: name, Version: "1.0.0", FixedVersion: fixed, Ecosystem: "pip"}}
	}
	if got := UpgradeTarget([]sarif.Result{pkg("urllib3", "2.0.0"), pkg("urllib3", "2.1.0")}); got != "2.1.0" {
		t.Errorf("UpgradeTarget = %q, want the release that clears both", got)
	}
	if got := UpgradeTarget([]sarif.Result{pkg("urllib3", "2.0.0"), pkg("jinja2", "3.1.5")}); got != "" {
		t.Errorf("UpgradeTarget = %q for two packages, which are two actions", got)
	}
}
