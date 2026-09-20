package scanpolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// signalConst finds the constants a package declares as a ranking signal: `SignalKEV = "kev"`.
var signalConst = regexp.MustCompile(`Signal[A-Za-z0-9_]*\s+=\s+"([^"]+)"`)

// The packages that may declare one. A new enrichment adds a directory here, which is a line in a
// test that fails loudly rather than a file nobody notices.
var signalPackages = []string{"../../pkg/exploit", "../../pkg/dephealth"}

// TestEverySignalDeclaresHowItComposes keeps a new ranking signal from silently inheriting an
// answer to the question its author is least likely to have asked.
//
// Signals compose, and the composition is where the surprises are. One written in isolation behaves
// correctly on its own and discards somebody else's evidence the first time both fire on one
// finding: a signal that raises a band also suppresses the reachability downgrade, so a flaw
// nothing can reach outranks the identical flaw somewhere it can, and nothing in the report says
// why. That is a decision, and it has to be written down rather than arrived at.
//
// Reads the constants rather than a list kept here, so adding a signal and forgetting this test
// fails the build instead of passing quietly.
func TestEverySignalDeclaresHowItComposes(t *testing.T) {
	t.Parallel()
	found := map[string]string{} // signal → where it was declared

	for _, dir := range signalPackages {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			// #nosec G304 -- dir is one of the two literals in signalPackages, and name came from
			// reading that directory.
			body, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			for _, m := range signalConst.FindAllStringSubmatch(string(body), -1) {
				found[m[1]] = filepath.Join(dir, name)
			}
		}
	}

	if len(found) == 0 {
		t.Fatal("no signal constants found at all; the pattern or the package list has gone stale")
	}

	for signal, where := range found {
		if _, declared := OverrulesUnreachable[signal]; !declared {
			t.Errorf("%q is declared in %s and says nothing about how it composes.\n"+
				"Add it to OverrulesUnreachable in signals.go, which decides whether it stands "+
				"against a verdict that nothing can reach the flaw. The doc comment there has the "+
				"question to ask.", signal, where)
		}
	}
	// And the other direction, so the table cannot outlive the signal it describes.
	for signal := range OverrulesUnreachable {
		if _, exists := found[signal]; !exists {
			t.Errorf("OverrulesUnreachable holds %q and no package declares it; a renamed signal "+
				"leaves this entry answering for nothing", signal)
		}
	}
}
