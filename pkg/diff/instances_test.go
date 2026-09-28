package diff

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// instance is one finding of a rule that can occur several times in one file, with the same
// message each time: a mutable action tag, a hardcoded credential pattern.
func instance(line int, hash, repo string) sarif.Result {
	r := sarif.Result{
		Tool: "semgrep", RuleID: "mutable-action-tag", Level: sarif.LevelWarning,
		Message: "step uses a mutable tag", Priority: "P1",
		Location:  sarif.Location{URI: ".github/workflows/ci.yml", StartLine: line},
		Component: "api", Repository: repo,
	}
	if hash != "" {
		r.PartialFingerprints = map[string]string{sarif.LineHashKey: hash}
	}
	return r
}

func report(rs ...sarif.Result) sarif.Report { return sarif.Report{Results: rs} }

func tally(d Result) [3]int { return [3]int{len(d.New), len(d.Unchanged), len(d.Fixed)} }

// A second instance of a flaw the file already has is a new finding, and the gate sees it. Keyed on
// identity alone the two collapse into one, the change reports nothing, and a P1 passes the gate.
func TestASecondInstanceInTheSameFileIsNew(t *testing.T) {
	for _, tc := range []struct{ name, first, second string }{
		{"fingerprinted", "A", "B"},
		{"without fingerprints", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Compare(
				report(instance(10, tc.first, "r1")),
				report(instance(10, tc.first, "r1"), instance(40, tc.second, "r1")),
			)
			if got := tally(d); got != [3]int{1, 1, 0} {
				t.Fatalf("new, unchanged, fixed = %v, want [1 1 0]", got)
			}
			if tripped := d.GateNew("", "P1"); len(tripped) != 1 {
				t.Errorf("the gate passed a new P1: tripped = %d", len(tripped))
			}
		})
	}
}

// Every instance is counted on both sides, so the head's count is the head scan's count.
func TestEveryInstanceIsCounted(t *testing.T) {
	d := Compare(
		report(instance(10, "A", "r1"), instance(20, "B", "r1"), instance(30, "C", "r1")),
		report(instance(10, "A", "r1"), instance(20, "B", "r1"), instance(30, "C", "r1")),
	)
	if got := tally(d); got != [3]int{0, 3, 0} {
		t.Errorf("new, unchanged, fixed = %v, want [0 3 0]", got)
	}
}

// Removing one of two instances fixes one finding, not none.
func TestRemovingOneOfTwoInstancesFixesOne(t *testing.T) {
	d := Compare(
		report(instance(10, "A", "r1"), instance(20, "B", "r1")),
		report(instance(10, "A", "r1")),
	)
	if got := tally(d); got != [3]int{0, 1, 1} {
		t.Fatalf("new, unchanged, fixed = %v, want [0 1 1]", got)
	}
	if d.Fixed[0].Location.StartLine != 20 {
		t.Errorf("fixed the instance at line %d, want the removed one at 20", d.Fixed[0].Location.StartLine)
	}
}

// Instances that moved keep their fingerprints and pair with themselves; instances whose
// surrounding lines were edited lose them and still pair, by identity, in line order.
func TestInstancesThatMovedOrWereEditedAroundAreUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		head sarif.Report
	}{
		{"moved", report(instance(55, "B", "r1"), instance(15, "A", "r1"))},
		{"edited around", report(instance(11, "A2", "r1"), instance(21, "B2", "r1"))},
		{"one of each", report(instance(11, "A2", "r1"), instance(90, "B", "r1"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Compare(report(instance(10, "A", "r1"), instance(20, "B", "r1")), tc.head)
			if got := tally(d); got != [3]int{0, 2, 0} {
				t.Errorf("new, unchanged, fixed = %v, want [0 2 0]", got)
			}
		})
	}
}

// A loose match must not take the base finding another one matches exactly. The suppression tells
// the pairings apart: paired by fingerprint both are unchanged, and paired greedily in line order
// one would read as accepted and the other as unaccepted, two decisions nobody made.
func TestAnExactMatchIsNotTakenByALooseOne(t *testing.T) {
	base := report(suppressed(instance(10, "A", "r1"), "sam"), instance(20, "B", "r1"))
	head := report(instance(5, "X", "r1"), suppressed(instance(30, "A", "r1"), "sam"))
	d := Compare(base, head)
	if len(d.Accepted) != 0 || len(d.Unaccepted) != 0 {
		t.Fatalf("accepted = %d, unaccepted = %d, want neither", len(d.Accepted), len(d.Unaccepted))
	}
	if got := tally(d); got != [3]int{0, 2, 0} {
		t.Errorf("new, unchanged, fixed = %v, want [0 2 0]", got)
	}
}

// Instances in two repositories are two sets. Adding one to the second repository is new there,
// however many the first repository has.
func TestInstancesInTwoRepositoriesDoNotPair(t *testing.T) {
	d := Compare(
		report(instance(10, "A", "r1"), instance(20, "B", "r1")),
		report(instance(10, "A", "r1"), instance(20, "B", "r1"), instance(10, "A", "r2")),
	)
	if got := tally(d); got != [3]int{1, 2, 0} {
		t.Fatalf("new, unchanged, fixed = %v, want [1 2 0]", got)
	}
	if d.New[0].Repository != "r2" {
		t.Errorf("new finding is in %q, want r2", d.New[0].Repository)
	}
}

// A result repeated exactly, place and all, is one finding.
func TestAnExactRepeatIsOneFinding(t *testing.T) {
	d := Compare(report(), report(instance(10, "A", "r1"), instance(10, "A", "r1")))
	if len(d.New) != 1 {
		t.Errorf("new = %d, want an exact repeat counted once", len(d.New))
	}
}
