package tools_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/tools"
)

// catalogDoc is the published table of everything Draugr orchestrates, relative to this
// package.
const catalogDoc = "../../docs/reference/catalog.md"

// TestCatalogDocumentsEveryTool asserts that every external binary in the tool catalog has a
// row in the published catalog.
//
// The registry is what `draugr doctor` checks and what a scan actually needs; the table is
// where someone looks to find out what to install before running one. Nothing links the two,
// so a tool can join the registry and never appear in the docs — the scan then fails on a
// binary the reader was never told to install, and the omission is invisible from either side.
//
// Utilities are matched against their own section, because a bare binary name like `git`
// occurs throughout the document in prose and commands, and a substring match would pass on
// any of them.
func TestCatalogDocumentsEveryTool(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Clean(catalogDoc))
	if err != nil {
		t.Fatalf("read %s: %v", catalogDoc, err)
	}
	doc := string(raw)

	utilities, ok := section(doc, "## Utilities")
	if !ok {
		t.Fatalf("%s has no '## Utilities' section — the heading moved, so this test is no longer checking anything", catalogDoc)
	}

	for name, tool := range tools.Catalog() {
		row := "| `" + name + "` |"

		switch tool.Category {
		case tools.CategoryUtility:
			if !strings.Contains(utilities, row) {
				t.Errorf("utility %q is in the tool catalog but has no row in the Utilities table of %s;\n"+
					"a user who needs it gets no install hint until a scan fails on the missing binary", name, catalogDoc)
			}
		case tools.CategoryScanner:
			if !strings.Contains(doc, row) && !strings.Contains(doc, "`"+name+"`") {
				t.Errorf("scanner binary %q is in the tool catalog but is not mentioned in %s", name, catalogDoc)
			}
		default:
			t.Errorf("tool %q has category %q, which is neither %q nor %q — the catalog table it belongs in is undefined",
				name, tool.Category, tools.CategoryScanner, tools.CategoryUtility)
		}
	}
}

// section returns the body of the markdown section introduced by heading, up to the next
// heading at the same level.
func section(doc, heading string) (string, bool) {
	_, body, found := strings.Cut(doc, heading)
	if !found {
		return "", false
	}
	if upToNextHeading, _, more := strings.Cut(body, "\n## "); more {
		body = upToNextHeading
	}
	return body, true
}
