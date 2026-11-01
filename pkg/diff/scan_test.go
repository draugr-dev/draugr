package diff

import (
	"bytes"
	"strings"
	"testing"

	fixlist "github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// dependency is a finding about a package, in api's repository.
func dependency(rule, name, fixed string, line int, priority string) sarif.Result {
	r := res("trivy", rule, sarif.LevelWarning, "requirements.txt", line, priority)
	r.Control, r.Component, r.Repository = "sca", "api", "https://github.com/acme/api"
	r.Package = &sarif.Package{Name: name, Version: "1.0.0", FixedVersion: fixed, Ecosystem: "pip"}
	return r
}

// The strips are the ones `draugr diff` draws, with the whole run's counts as one more.
func TestAScanViewDrawsTheStripsAndTheWholeRun(t *testing.T) {
	r := Compare(sarif.Report{}, sarif.Report{Results: []sarif.Result{dependency("CVE-1", "urllib3", "2.0.0", 3, "P2")}})
	var b bytes.Buffer
	ScanView{Result: r}.WriteStrips(&b, "whole run", [4]int{1, 2, 3, 4})
	for _, want := range []string{"new        0 P1 1 P2 0 P3 0 P4", "whole run  1 P1 2 P2 3 P3 4 P4"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("strips do not draw %q:\n%s", want, b.String())
		}
	}
}

// What changed is drawn in the view the scan was asked for, and nothing at all is drawn where
// nothing changed, because the scan's verdict line already says so.
func TestAScanViewListsWhatChanged(t *testing.T) {
	head := []sarif.Result{
		dependency("CVE-1", "urllib3", "2.0.0", 3, "P2"),
		dependency("CVE-2", "urllib3", "2.1.0", 3, "P2"),
		dependency("CVE-3", "jinja2", "", 2, "P3"),
	}
	r := Compare(sarif.Report{}, sarif.Report{Results: head})
	r.Gate, r.Tripped = Gate{FailOnPriority: "P2"}, r.GateNew("", "P2")
	v := ScanView{Result: r}

	for _, tc := range []struct {
		view      fixlist.View
		top       int
		want, not []string
	}{
		// An upgrade names the release the scan's own fix list names, the highest of the two, and an
		// upgrade with no release to move to names none.
		{fixlist.ViewActions, 0, []string{"Upgrade urllib3 1.0.0 → 2.1.0", "Upgrade jinja2 1.0.0  "}, []string{"jinja2 1.0.0 →"}},
		{fixlist.ViewFindings, 0, []string{"CHANGED  3, by priority", "CVE-1 msg"}, nil},
		{fixlist.ViewCompact, 0, []string{"CHANGED  3, by priority"}, []string{"CVE-1 msg"}},
		{fixlist.ViewFindings, 1, []string{"top 1 of 3", "… and 2 changed findings not listed."}, nil},
	} {
		var b bytes.Buffer
		if !v.WriteListing(&b, tc.view, tc.top) {
			t.Fatalf("%s: wrote nothing for three new findings", tc.view)
		}
		for _, want := range tc.want {
			if !strings.Contains(b.String(), want) {
				t.Errorf("%s --top %d does not say %q:\n%s", tc.view, tc.top, want, b.String())
			}
		}
		for _, not := range tc.not {
			if strings.Contains(b.String(), not) {
				t.Errorf("%s --top %d says %q:\n%s", tc.view, tc.top, not, b.String())
			}
		}
	}

	var b bytes.Buffer
	if (ScanView{Result: Compare(sarif.Report{Results: head}, sarif.Report{Results: head})}).WriteListing(&b, fixlist.ViewFindings, 0) || b.Len() > 0 {
		t.Errorf("nothing changed and the listing wrote %q", b.String())
	}
}

// A finding that moved to another component is the one change with nothing new, fixed or accepted
// beside it, and it is still drawn.
func TestAScanViewDrawsAMoveWhenNothingElseChanged(t *testing.T) {
	was := dependency("CVE-1", "urllib3", "2.0.0", 3, "P2")
	now := was
	now.Component = "checkout"
	var b bytes.Buffer
	v := ScanView{Result: Compare(sarif.Report{Results: []sarif.Result{was}}, sarif.Report{Results: []sarif.Result{now}})}
	if !v.WriteListing(&b, fixlist.ViewFindings, 0) || !strings.Contains(b.String(), "MOVED") {
		t.Errorf("a move was not drawn:\n%s", b.String())
	}
	if strings.Contains(b.String(), "CHANGED") {
		t.Errorf("a move alone drew an empty CHANGED table:\n%s", b.String())
	}
}

// `draugr diff`'s own actions keep the title they had: the target is the scan's, where the fix list
// beside it names one.
func TestDiffActionsNameNoTargetOfTheirOwn(t *testing.T) {
	r := Compare(sarif.Report{}, sarif.Report{Results: []sarif.Result{dependency("CVE-1", "urllib3", "2.0.0", 3, "P2")}})
	var b bytes.Buffer
	if err := Render(&b, "console", r, Options{View: ViewActions}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "→ 2.0.0") {
		t.Errorf("draugr diff's actions named a target:\n%s", b.String())
	}
}
