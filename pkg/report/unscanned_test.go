package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// imageTargets is the run's account of three images, every one failed for the same component.
func imageTargets(component string, refs ...string) []engine.TargetOutcome {
	out := make([]engine.TargetOutcome, 0, len(refs))
	for _, r := range refs {
		out = append(out, engine.TargetOutcome{Kind: "image", Target: r, Status: engine.TargetFailed,
			Detail:     "trivy image " + r + ": GET https://" + r + ": MANIFEST_UNKNOWN: manifest unknown",
			Components: []string{component}})
	}
	return out
}

// TestComponentWithNothingScannedDoesNotPass is the false negative this exists to remove.
//
// A component whose whole surface is three images, none of which could be pulled, was rendering
// as `pass  no findings`. Nothing looked at it, so there were no findings to have, and a row
// saying so beside the word "pass" is the report asserting something no scanner established.
func TestComponentWithNothingScannedDoesNotPass(t *testing.T) {
	refs := []string{"registry.example.com/a:1", "registry.example.com/b:1", "registry.example.com/c:1"}
	d := Data{
		Release: saga.Release{Version: "1.0"},
		Run:     engine.Result{Targets: imageTargets("mesh", refs...)},
		Verdict: norn.Result{Verdict: norn.Fail},
		Components: []ComponentVerdict{{
			Name:    "mesh",
			Verdict: norn.Pass, // the policy saw no findings, because none were possible
			Unscanned: []engine.Unscanned{
				{Control: "images", Kind: "image", Target: refs[0]},
				{Control: "images", Kind: "image", Target: refs[1]},
				{Control: "images", Kind: "image", Target: refs[2]},
			},
		}},
	}

	out := renderWith(t, consoleReporter{}, d)
	if !strings.Contains(out, "mesh  ERROR") {
		t.Errorf("a component nothing was scanned for is not a pass:\n%s", out)
	}
	// What went unexamined is said once, by target, with the component it leaves unscanned.
	for _, want := range []string{
		"ERRORS  3 of 3 targets not reached",
		"image registry.example.com/a:1  mesh        manifest unknown",
		"image registry.example.com/c:1  mesh        manifest unknown",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// TestComponentWithFindingsAndAGapReportsBoth: a component that was partly scanned has findings
// worth acting on *and* a gap. The findings are not the whole picture, so the row is an error, and
// the gap does not mean nothing was found, so the counts stay beside it.
func TestComponentWithFindingsAndAGapReportsBoth(t *testing.T) {
	d := Data{
		Release: saga.Release{Version: "1.0"},
		Run:     engine.Result{Targets: imageTargets("api", "r/a:1")},
		Verdict: norn.Result{Verdict: norn.Fail},
		Components: []ComponentVerdict{{
			Name: "api", Verdict: norn.Fail, Findings: 4, Priorities: [4]int{2, 2, 0, 0},
			Controls:  []string{"sca"},
			Unscanned: []engine.Unscanned{{Control: "images", Kind: "image", Target: "r/a:1"}},
		}},
	}
	out := renderWith(t, consoleReporter{}, d)
	if !strings.Contains(out, "api  ERROR  2 P1 2 P2") {
		t.Errorf("the row should be an error and keep its findings:\n%s", out)
	}
	if !strings.Contains(out, "image r/a:1  api") {
		t.Errorf("the gap is missing:\n%s", out)
	}
}

// TestEveryFormatRefusesToPassAComponentNobodyScanned. The rule is the console's and it has to
// hold wherever the breakdown is drawn: a row of four zeros beside the word "pass" asserts
// something no scanner established, and in a table it reads most like a result.
func TestEveryFormatRefusesToPassAComponentNobodyScanned(t *testing.T) {
	d := Data{
		Release: saga.Release{Version: "1.0"},
		Run:     engine.Result{Targets: imageTargets("mesh", "r/a:1")},
		Verdict: norn.Result{Verdict: norn.Fail},
		Components: []ComponentVerdict{{
			Name: "mesh", Verdict: norn.Pass,
			Unscanned: []engine.Unscanned{{Control: "images", Kind: "image", Target: "r/a:1"}},
			Declared:  map[string]int{"image": 1},
		}},
	}
	for r, want := range map[Reporter]string{
		consoleReporter{}:  "image r/a:1  mesh",
		markdownReporter{}: "1/1 image not scanned",
		htmlReporter{}:     "1/1 image not scanned",
	} {
		t.Run(r.Format(), func(t *testing.T) {
			out := renderWith(t, r, d)
			if !strings.Contains(out, "ERROR") {
				t.Errorf("a component nothing was scanned for is not a pass:\n%s", out)
			}
			if !strings.Contains(out, want) {
				t.Errorf("the report does not say what went unexamined, want %q:\n%s", want, out)
			}
		})
	}
}

// A component that passed on what was read and has a target nobody read is one verdict in every
// format. A copy that says PASS where the terminal says ERROR is the one that gets shared.
func TestEveryFormatMarksAPartlyScannedComponentAnError(t *testing.T) {
	d := Data{
		Release: saga.Release{Version: "1.0"},
		Run:     engine.Result{Targets: imageTargets("worker", "r/a:1")},
		Verdict: norn.Result{Verdict: norn.Pass},
		Components: []ComponentVerdict{{
			Name: "worker", Verdict: norn.Pass, Findings: 2, Priorities: [4]int{0, 0, 1, 1},
			Unscanned: []engine.Unscanned{{Control: "images", Kind: "image", Target: "r/a:1"}},
			Declared:  map[string]int{"image": 3},
		}},
	}
	for r, want := range map[Reporter]string{
		consoleReporter{}:  "worker  ERROR",
		markdownReporter{}: "| worker | - | **ERROR** |",
		htmlReporter{}:     `<td><span class="err">ERROR</span></td>`,
	} {
		t.Run(r.Format(), func(t *testing.T) {
			if out := renderWith(t, r, d); !strings.Contains(out, want) {
				t.Errorf("want %q:\n%s", want, out)
			}
		})
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
			// Declared as `kubernetes:` and counted under that kind, read as clusters.
			name:     "a kubernetes target is a cluster",
			us:       []engine.Unscanned{{Kind: "kubernetes"}},
			declared: map[string]int{"kubernetes": 2},
			want:     "1/2 clusters not scanned",
		},
		{
			// Nothing declared this kind. A project-wide target, say. So there is no denominator to give
			// and inventing one would be worse than the bare count.
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
