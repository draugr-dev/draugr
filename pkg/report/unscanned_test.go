package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// TestComponentWithNothingScannedDoesNotPass is the false negative this exists to remove.
//
// A component whose whole surface is three images, none of which could be pulled, was rendering
// as `pass  no findings`. Nothing looked at it, so there were no findings to have — and a row
// saying so beside the word "pass" is the report asserting something no scanner established.
func TestComponentWithNothingScannedDoesNotPass(t *testing.T) {
	d := Data{
		Release: saga.Release{Name: "app", Version: "1.0"},
		Verdict: norn.Result{Verdict: norn.Fail},
		Components: []ComponentVerdict{{
			Name:    "mesh",
			Verdict: norn.Pass, // the policy saw no findings, because none were possible
			Unscanned: []engine.Unscanned{
				{Control: "images", Kind: "image", Target: "registry.example.com/a:1"},
				{Control: "images", Kind: "image", Target: "registry.example.com/b:1"},
				{Control: "images", Kind: "image", Target: "registry.example.com/c:1"},
			},
		}},
	}

	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if strings.Contains(out, "no findings") {
		t.Errorf("a component nothing was scanned for claimed no findings:\n%s", out)
	}
	if !strings.Contains(out, "3 images not scanned") {
		t.Errorf("the row should say what went unexamined:\n%s", out)
	}
	if !strings.Contains(out, "ERROR") {
		t.Errorf("a component nothing was scanned for is not a pass:\n%s", out)
	}
}

// TestComponentWithFindingsAndAGapReportsBoth: a component that was partly scanned has findings
// worth acting on *and* a gap, and dropping either reading is wrong.
func TestComponentWithFindingsAndAGapReportsBoth(t *testing.T) {
	d := Data{
		Release: saga.Release{Name: "app", Version: "1.0"},
		Verdict: norn.Result{Verdict: norn.Fail},
		Components: []ComponentVerdict{{
			Name: "api", Verdict: norn.Fail, Findings: 4, Priorities: [4]int{2, 2, 0, 0},
			Controls:  []string{"sca"},
			Unscanned: []engine.Unscanned{{Control: "images", Kind: "image", Target: "r/a:1"}},
		}},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 image not scanned") {
		t.Errorf("the gap is missing:\n%s", out)
	}
	if !strings.Contains(out, "P1 2") {
		t.Errorf("the findings are missing:\n%s", out)
	}
}

func TestUnscannedDetailCountsByKind(t *testing.T) {
	got := unscannedDetail([]engine.Unscanned{
		{Kind: "image"}, {Kind: "image"}, {Kind: "repository"}, {Kind: ""},
	})
	// Counted rather than listed: the control's error above says why, and this says what.
	const want = "2 images, 1 repository, 1 target not scanned"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
