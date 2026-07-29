package builtins

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every controller, scanner and surveyor ships a colocated `.md` beside its code, and a row in
// the integrations catalog linking to it.
//
// The requirement is easy to satisfy and easy to overlook: a plugin with no documentation still
// compiles, still passes its own tests, and still runs. Nothing about it looks wrong until
// someone goes looking for the docs. The website generates its documentation from this
// repository, so a gap here becomes a gap there. It is mechanically checkable, so it is checked
// rather than left to a reviewer remembering.
//
// The catalog assertion matters as much as the file one: a doc nothing links to is a doc nobody
// finds, and the catalog is the page the website, the README and the disclaimer all point at.

// repoRoot resolves the checkout root from this package's directory.
const repoRoot = "../.."

const catalogPath = "docs/reference/catalog.md"

func TestEveryPluginHasColocatedDocs(t *testing.T) {
	catalog := readCatalog(t)
	reg := Registry()

	for _, c := range reg.Controllers() {
		assertDocumented(t, catalog, "controller", "internal/controllers", c.Info().Name)
	}
	for _, s := range reg.Scanners() {
		assertDocumented(t, catalog, "scanner", "internal/scanners", s.Info().Name)
	}
	for _, name := range SurveyorRegistry().Names() {
		assertDocumented(t, catalog, "surveyor", "internal/surveyors", name)
	}
}

// assertDocumented checks that a plugin has its colocated doc and that the catalog links to it.
func assertDocumented(t *testing.T, catalog, kind, dir, name string) {
	t.Helper()
	rel := filepath.Join(dir, name+".md")

	if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
		t.Errorf("%s %q has no colocated doc at %s\n"+
			"  Every %s ships one: what it does, the tool behind it, its licence and terms of\n"+
			"  use, and integration notes. Copy the shape of an existing neighbour in %s/.",
			kind, name, rel, kind, dir)
		return // no point reporting a missing link to a file that doesn't exist
	}

	// The catalog lives two directories down, so its links are relative in this one form.
	if link := "(../../" + rel + ")"; !strings.Contains(catalog, link) {
		t.Errorf("%s %q is not linked from %s\n"+
			"  Add a row whose Doc column is [doc]%s, so the page the website and README point\n"+
			"  at actually reaches it.",
			kind, name, catalogPath, link)
	}
}

func readCatalog(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, catalogPath))
	if err != nil {
		t.Fatalf("read %s: %v", catalogPath, err)
	}
	return string(b)
}
