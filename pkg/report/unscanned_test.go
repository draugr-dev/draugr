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

// TestUnscannedDetailSaysHowMuchOfTheComponent covers the difference between a component nothing
// looked at and a gap in one that was mostly covered. The bare count reads as the first either
// way, and only one of them is a reason to stop and fix the scan.
func TestUnscannedDetailSaysHowMuchOfTheComponent(t *testing.T) {
	for _, c := range []struct {
		name, want string
		us         []engine.Unscanned
		declared   map[string]int
	}{
		{
			name:     "all of them",
			us:       []engine.Unscanned{{Kind: "image"}, {Kind: "image"}, {Kind: "image"}},
			declared: map[string]int{"image": 3},
			want:     "3/3 images not scanned",
		},
		{
			name:     "some of them",
			us:       []engine.Unscanned{{Kind: "image"}},
			declared: map[string]int{"image": 30},
			want:     "1/30 images not scanned",
		},
		{
			name:     "one of one reads as singular",
			us:       []engine.Unscanned{{Kind: "repository"}},
			declared: map[string]int{"repository": 1},
			want:     "1/1 repository not scanned",
		},
		{
			name:     "several kinds",
			us:       []engine.Unscanned{{Kind: "image"}, {Kind: "image"}, {Kind: "repository"}},
			declared: map[string]int{"image": 2, "repository": 4},
			want:     "2/2 images, 1/4 repositories not scanned",
		},
		{
			// Nothing declared this kind — a project-wide target, say — so there is no
			// denominator to give and inventing one would be worse than the bare count.
			name:     "no denominator to give",
			us:       []engine.Unscanned{{Kind: ""}},
			declared: nil,
			want:     "1 target not scanned",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := unscannedDetail(c.us, c.declared); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}
