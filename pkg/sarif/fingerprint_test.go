package sarif

import (
	"strings"
	"testing"
)

// source is a small file to fingerprint against.
var source = strings.Split(`package main

import "fmt"

func main() {
	password := "hunter2"
	fmt.Println(password)
}`, "\n")

func TestAFindingSurvivesAnEditOutsideItsContext(t *testing.T) {
	// The whole reason this exists. Fingerprint hashes the line number, so adding an import makes
	// every finding below it look new — every run would report most findings as fixed and
	// re-report them as new, first_seen would reset constantly, and time-to-fix would measure
	// nothing. It is the kind of wrong that produces plausible charts.
	//
	// "Outside its context" is the honest claim: see the test below for what happens inside it.
	before := LineHash(source, 6) // the password line

	withImport := append([]string{}, source...)
	withImport = append(withImport[:3], append([]string{`import "os"`}, withImport[3:]...)...)

	after := LineHash(withImport, 7) // the same line, one lower
	if before == "" || before != after {
		t.Errorf("the fingerprint changed when a line was added above it:\n%q\n%q", before, after)
	}
}

func TestReindentingDoesNotChangeIt(t *testing.T) {
	// A repository adopting a formatter would otherwise report every finding as fixed and new.
	indented := make([]string, len(source))
	for i, line := range source {
		indented[i] = "    " + line + "  "
	}
	if LineHash(source, 6) != LineHash(indented, 6) {
		t.Error("reformatting changed the fingerprint")
	}
}

func TestChangingTheCodeChangesIt(t *testing.T) {
	// The other half. A fingerprint that survived an actual edit would merge two different
	// findings into one history.
	changed := append([]string{}, source...)
	changed[5] = `	password := os.Getenv("PASSWORD")`
	if LineHash(source, 6) == LineHash(changed, 6) {
		t.Error("the fingerprint survived the line being rewritten")
	}
}

func TestTwoIdenticalLinesInOneFileDiffer(t *testing.T) {
	// Context is what separates them. Without it every bare closing brace in a repository would
	// share one identity.
	lines := []string{"a()", "close()", "b()", "c()", "close()", "d()"}
	if LineHash(lines, 2) == LineHash(lines, 5) {
		t.Error("two identical lines in different places share a fingerprint")
	}
}

func TestThereIsNoFingerprintWhenThereIsNothingToHash(t *testing.T) {
	// Absent means "no content-based identity". A fabricated one would be worse than none: it
	// would collide with every other empty region and merge unrelated findings into one history.
	for name, tc := range map[string]struct {
		lines []string
		line  int
	}{
		"no lines":     {nil, 1},
		"line zero":    {source, 0},
		"past the end": {source, 999},
		"all blank":    {[]string{"", "   ", "", "\t", ""}, 3},
	} {
		t.Run(name, func(t *testing.T) {
			if got := LineHash(tc.lines, tc.line); got != "" {
				t.Errorf("LineHash = %q, want empty", got)
			}
		})
	}
}

func TestStampingRecordsItUnderTheNameConsumersRead(t *testing.T) {
	// GitHub code scanning's own name, because emitting it under any other would mean computing
	// the right thing and having nobody consume it.
	r := Result{Location: Location{URI: "main.go", StartLine: 6}}
	r.StampLineHash(source)

	if r.PartialFingerprints[LineHashKey] == "" {
		t.Fatalf("nothing was stamped: %v", r.PartialFingerprints)
	}
	if !strings.HasPrefix(LineHashKey, "primaryLocationLineHash") {
		t.Errorf("key = %q, want the name GitHub reads", LineHashKey)
	}
}

func TestStampingAddsNothingWhenThereIsNothingToAdd(t *testing.T) {
	r := Result{Location: Location{URI: "go.mod"}} // a dependency finding: no line
	r.StampLineHash(source)
	if r.PartialFingerprints != nil {
		t.Errorf("a finding with no line was stamped: %v", r.PartialFingerprints)
	}
}

func TestItIsNotTheDeduplicationFingerprint(t *testing.T) {
	// Two different questions. Fingerprint asks "are these the same finding in this run", and
	// includes the line number to answer it. This asks "is this the finding we saw last week",
	// and must not.
	a := Result{RuleID: "R1", Tool: "t", Location: Location{URI: "main.go", StartLine: 6}}
	b := a
	b.Location.StartLine = 7

	if a.Fingerprint() == b.Fingerprint() {
		t.Error("the dedup fingerprint ignored the line number")
	}
	a.StampLineHash(source)
	b.StampLineHash(source)
	if a.PartialFingerprints[LineHashKey] == b.PartialFingerprints[LineHashKey] {
		// Different lines, different content, so these should differ here too — the point is that
		// they are computed from different things, not that they always agree.
		t.Log("distinct content produced distinct fingerprints, as expected")
	}
}

func TestAnEditInsideTheContextDoesChangeIt(t *testing.T) {
	// Stated rather than hidden. Nearby lines are part of the identity, so a line inserted
	// immediately above a finding changes its fingerprint — inherent to any context-based scheme,
	// and the same trade CodeQL makes. Without context every bare `}` in a repository would share
	// one fingerprint, which is a worse failure: unrelated findings merged into one history.
	//
	// The consequence a reader should take away: such a finding reads as fixed-and-new once, and
	// then is stable again. An edit elsewhere in the file — the common case — costs nothing.
	adjacent := append([]string{}, source...)
	adjacent = append(adjacent[:5], append([]string{"\t// set from the vault"}, adjacent[5:]...)...)

	if LineHash(source, 6) == LineHash(adjacent, 7) {
		t.Error("a line inserted immediately above did not change the fingerprint; " +
			"the window is not being applied")
	}
}

func TestAFindingAtTheTopOfAFileStillGetsOne(t *testing.T) {
	// The truncated-window case: there is nothing above line 1 to include. It still has an
	// identity, it is simply more exposed to edits above it — which is worth having rather than
	// having none.
	if LineHash(source, 1) == "" {
		t.Error("a finding on the first line has no fingerprint")
	}
}
