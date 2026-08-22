package publish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every registered publisher is documented in all three places a reader looks.
//
// The requirement is easy to satisfy and easy to lose: a publisher with no documentation still
// compiles, still registers, and still runs, and nothing about the repository looks wrong until
// somebody goes looking. It has been lost by accident too — a branch rebuilt from an older base
// carried an older copy of a shared docs file, and the merge reverted another change's section
// with git reporting no conflict at all. Nobody reviewing either pull request would have seen it.
//
// So it is checked rather than left to a reviewer remembering, and checked against the live
// registry so adding a kind is what triggers the requirement.
//
// The three are not redundant. The catalog is what the website, the README and the disclaimer all
// point at; the guide is where somebody learns to use it; the schema reference is where somebody
// reading a descriptor looks up a key. A publisher missing from any one of them is invisible to
// whoever started there.
var publisherDocs = []struct {
	path string
	what string
}{
	{"docs/reference/catalog.md", "the catalog every other page links to"},
	{"docs/guides/reports-and-publishers.md", "the guide that explains how to use one"},
	{"docs/reference/saga-schema.md", "the descriptor reference"},
}

const repoRoot = "../.."

func TestEveryPublisherIsDocumented(t *testing.T) {
	for _, doc := range publisherDocs {
		content, err := os.ReadFile(filepath.Join(repoRoot, doc.path))
		if err != nil {
			t.Fatalf("read %s: %v", doc.path, err)
		}
		text := string(content)

		for _, kind := range Kinds() {
			if !strings.Contains(text, kind) {
				t.Errorf("publisher %q is not in %s (%s).\n"+
					"A publisher nobody documented is one nobody finds, whichever page they "+
					"started from.", kind, doc.path, doc.what)
			}
		}
	}
}

func TestTheDocumentedPublishersAllExist(t *testing.T) {
	// The other direction. A row for a publisher that was renamed or removed sends a reader to
	// configure a kind the binary will refuse, and the error they get names every kind except the
	// one they just read about.
	content, err := os.ReadFile(filepath.Join(repoRoot, "docs/reference/catalog.md"))
	if err != nil {
		t.Fatal(err)
	}

	registered := map[string]bool{}
	for _, k := range Kinds() {
		registered[k] = true
	}
	for _, line := range strings.Split(string(content), "\n") {
		// The catalog's publisher rows open with the kind in backticks.
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		kind := strings.TrimSuffix(strings.TrimPrefix(strings.SplitN(line, "|", 3)[1], " `"), "` ")
		// Only rows naming something publisher-shaped; the file also catalogs scanners.
		if !strings.Contains(line, "publisher") && !strings.Contains(line, "posts the") &&
			!strings.Contains(line, "uploads the") && !strings.Contains(line, "a local directory") {
			continue
		}
		if !registered[kind] {
			t.Errorf("the catalog documents publisher %q, which is not registered. "+
				"A reader configuring it gets an error listing every kind except that one.", kind)
		}
	}
}
