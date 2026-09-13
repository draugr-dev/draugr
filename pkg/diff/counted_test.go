package diff

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// oneFlawTwoScanners is what a component carrying a library both in a lockfile and as a file
// produces: the manifest scanner's finding, and the file scanner's copy of it, marked as counted
// under the first.
func oneFlawTwoScanners() sarif.Report {
	return sarif.Report{Results: []sarif.Result{
		{
			RuleID: "CVE-2020-11023", Tool: "trivy", Level: sarif.LevelError, Priority: "P1",
			Location:    sarif.Location{URI: "web/package-lock.json", StartLine: 10},
			Correlation: &sarif.Correlation{AlsoFoundBy: []sarif.Observation{{Tool: "retirejs", Severity: sarif.SeverityMedium}}},
		},
		{
			RuleID: "CVE-2020-11023", Tool: "retirejs", Level: sarif.LevelError, Priority: "P1",
			Location:    sarif.Location{URI: "web/static/js/jquery.min.js"},
			Correlation: &sarif.Correlation{CountedUnder: "trivy"},
		},
	}}
}

// A change introducing one flaw that two scanners report is one change, in every place a number
// is stated. The scan of the same head says one; a diff saying two puts two answers to one
// question in front of the same reader, and the diff's is the one that reaches a pull request.
func TestOneFlawTwoScannersIsOneChange(t *testing.T) {
	r := Compare(sarif.Report{}, oneFlawTwoScanners())

	if got := len(r.New); got != 2 {
		t.Fatalf("Compare kept %d new, want both copies: nothing is deleted", got)
	}

	c := r.Counted()
	if got := len(c.New); got != 1 {
		t.Errorf("Counted().New = %d, want 1", got)
	}
	if got := c.New[0].Tool; got != "trivy" {
		t.Errorf("kept %q, want the scanner the flaw is counted under", got)
	}
	if got := len(c.Changed()); got != 1 {
		t.Errorf("Changed() = %d rows, want 1", got)
	}
	if got, want := newBands(c.New), [4]int{1, 0, 0, 0}; got != want {
		t.Errorf("newBands = %v, want %v", got, want)
	}
}

// The same, the other way round: a flaw two scanners found and somebody then fixed is one fix,
// not two. Good news doubled is the same defect as bad news doubled.
func TestAFixedFlawTwoScannersFoundIsOneFix(t *testing.T) {
	c := Compare(oneFlawTwoScanners(), sarif.Report{}).Counted()
	if got := len(c.Fixed); got != 1 {
		t.Errorf("Counted().Fixed = %d, want 1", got)
	}
}

// Every rendered format states the same number, and the console says which other scanner found it.
func TestEveryFormatCountsTheFlawOnce(t *testing.T) {
	r := Compare(sarif.Report{}, oneFlawTwoScanners())
	for _, tc := range []struct {
		format string
		opts   Options
		want   string
	}{
		{"console", Options{}, "1 new"},
		{"console", Options{View: ViewActions}, "1 new"},
		{"console", Options{View: ViewCompact}, "1 new"},
		{"markdown", Options{}, "🔺 1 new"},
		{"json", Options{}, `"new": 1`},
	} {
		t.Run(tc.format+"/"+string(tc.opts.View), func(t *testing.T) {
			var b bytes.Buffer
			if err := Render(&b, tc.format, r, tc.opts); err != nil {
				t.Fatalf("render: %v", err)
			}
			if !strings.Contains(b.String(), tc.want) {
				t.Errorf("%s does not say %q:\n%s", tc.format, tc.want, b.String())
			}
			if strings.Contains(b.String(), "jquery.min.js") {
				t.Errorf("%s draws the copy as its own row:\n%s", tc.format, b.String())
			}
		})
	}

	var b bytes.Buffer
	if err := Render(&b, "console", r, Options{}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(b.String(), "also found by retirejs") {
		t.Errorf("the row does not say a second scanner found it:\n%s", b.String())
	}
}

// The SARIF keeps what each scanner said. It is what the head scan's own report carries, and
// dropping a scanner's finding from the record is the thing "suppress, don't delete" refuses.
func TestTheDiffSARIFKeepsBothScannersFindings(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, "sarif", Compare(sarif.Report{}, oneFlawTwoScanners()), Options{}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(b.String(), "jquery.min.js") {
		t.Errorf("the record lost what retirejs found:\n%s", b.String())
	}
}

// Counted returns the input untouched when there is nothing to drop, which is nearly every run.
func TestCountedLeavesAnUncorrelatedRunAlone(t *testing.T) {
	head := sarif.Report{Results: []sarif.Result{
		{RuleID: "CVE-1", Tool: "trivy", Level: sarif.LevelError, Priority: "P1"},
	}}
	r := Compare(sarif.Report{}, head)
	if got := len(r.Counted().New); got != 1 {
		t.Errorf("Counted().New = %d, want 1", got)
	}
}

// The gate already skipped the copies, and it keeps doing so: nothing here moves the verdict.
func TestCountingDoesNotMoveTheGate(t *testing.T) {
	r := Compare(sarif.Report{}, oneFlawTwoScanners())
	before := len(r.GateNew("", "P1"))
	if got := len(r.Counted().GateNew("", "P1")); got != before || before != 1 {
		t.Errorf("gate tripped on %d before and %d after, want 1 both times", before, got)
	}
}
