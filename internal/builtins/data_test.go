package builtins

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// A scanner that reads reference data warms it.
//
// Without a warm, a run fetches once per job rather than once, which on a cold cache is several
// jobs racing to download the same file. Data the tool re-fetches on every invocation is exempt
// and says so in the declaration, because there is nothing to warm into.
//
// The converse, that a scanner warming something declares what, is not checkable here: the shared
// repoScanner satisfies plugin.Prewarmer for every tool built on it and no-ops where nothing is
// wired, so the assertion answers a question about the adapter rather than about the scanner. The
// doc check below covers a scanner that fetches and declares nothing, because a sentence is
// something a person has to write.
func TestAScannerThatReadsDataWarmsIt(t *testing.T) {
	for _, s := range Registry().Scanners() {
		info := s.Info()
		var warmable bool
		for _, d := range info.Data {
			if !d.PerScan {
				warmable = true
			}
		}
		if !warmable {
			continue
		}
		if _, ok := s.(plugin.Prewarmer); !ok {
			t.Errorf("scanner %q declares data it could warm and implements no plugin.Prewarmer, "+
				"so a run fetches it once per job rather than once", info.Name)
		}
	}
}

// Every declared source says what it is and where it comes from.
//
// A host is the field with a reader outside this repository: it is what goes in an allowlist, and
// a source without one describes a fetch nobody can permit.
func TestEveryDeclaredSourceNamesItselfAndItsHosts(t *testing.T) {
	for _, s := range Registry().Scanners() {
		for _, d := range s.Info().Data {
			if d.Name == "" {
				t.Errorf("scanner %q declares a source with no name", s.Info().Name)
			}
			if len(d.Hosts) == 0 {
				t.Errorf("scanner %q declares %q with no host, so nothing can allow it",
					s.Info().Name, d.Name)
			}
			for _, h := range d.Hosts {
				if strings.ContainsAny(h, "/: ") {
					t.Errorf("scanner %q names host %q; a host, not a URL, is what an allowlist takes",
						s.Info().Name, h)
				}
			}
		}
	}
}

// dataSection matches however a doc states what its tool fetches. The house style is a `## Data`
// heading; a bullet is equally fine.
var dataSection = regexp.MustCompile(`(?im)^#+\s*Data\b|^\s*[-*]\s*\*\*Data`)

// Every tool doc says what it reads from outside, including the ones that read nothing.
//
// The code declaration cannot tell "this fetches nothing" from "nobody thought about it", and both
// produce an empty Data. A sentence a person had to write can, which is the same argument the
// terms check rests on. A scanner whose rules travel in its own binary says that, and it is an
// answer.
func TestEveryToolDocSaysWhatItReads(t *testing.T) {
	for _, s := range Registry().Scanners() {
		info := s.Info()
		path := filepath.Join(repoRoot, "internal/scanners", info.Name+".md")
		body, err := os.ReadFile(path) //nolint:gosec // a path built from the registry, inside this repo
		if err != nil {
			continue // the colocated-docs test reports a missing file, and better
		}
		if !dataSection.Match(body) {
			t.Errorf("scanner %q does not say what it reads from outside (%s)", info.Name, path)
			t.Log("  Add a `## Data` section. A scanner that fetches nothing says so;\n" +
				"  one that fetches names the host, so a reader behind an allowlist can permit it.")
			continue
		}
		// Declared hosts and documented hosts are one fact, and a second copy is the one that drifts.
		for _, d := range info.Data {
			for _, h := range d.Hosts {
				if !strings.Contains(string(body), h) {
					t.Errorf("scanner %q declares host %q and its doc does not name it (%s)",
						info.Name, h, path)
				}
			}
		}
	}
}
