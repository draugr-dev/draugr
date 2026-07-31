package builtins

import (
	"os"
	"path/filepath"
	"slices"
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

// TestCatalogNamesTheRealDefaultScanner holds the published catalog to the registry on the one
// claim most likely to rot: which scanner a control runs by default.
//
// Same-PR doc discipline keeps the pages *next to* a change correct. It does not catch a page
// elsewhere that the change quietly falsified — and "the default is X" is exactly that kind of
// claim, written once in a table nobody revisits and read by everyone deciding what a scan does.
// The catalog said kube-bench was the infrastructure default for a release after it stopped
// being true.
//
// Only controls with more than one scanner are checked. Where there is one, "default" is not a
// claim anyone can get wrong.
func TestCatalogNamesTheRealDefaultScanner(t *testing.T) {
	t.Parallel()

	doc := readCatalog(t)

	reg := Registry()
	scannersFor := map[string][]string{}
	for _, s := range reg.Scanners() {
		for _, control := range s.Info().Controls {
			scannersFor[control] = append(scannersFor[control], s.Info().Name)
		}
	}

	checked := 0
	for _, c := range reg.Controllers() {
		info := c.Info()
		if len(info.DefaultScanners) == 0 || len(scannersFor[info.Name]) < 2 {
			continue
		}
		row, ok := catalogRow(doc, info.Name)
		if !ok {
			t.Errorf("control %q has no row in %s", info.Name, catalogPath)
			continue
		}
		checked++
		for _, want := range info.DefaultScanners {
			if !strings.Contains(row, "`"+want+"` (default)") {
				t.Errorf("%s runs %q by default, but the catalog row does not say so:\n  %s",
					info.Name, want, strings.TrimSpace(row))
			}
		}
		// And nothing else may claim to be the default.
		for _, other := range scannersFor[info.Name] {
			if slices.Contains(info.DefaultScanners, other) {
				continue
			}
			if strings.Contains(row, "`"+other+"` (default)") {
				t.Errorf("the catalog calls %q the default for %s, but it is not:\n  %s",
					other, info.Name, strings.TrimSpace(row))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no multi-scanner control was checked — a guard that checks nothing is worse than no guard")
	}
}

// catalogRow returns the controllers-table row for a control.
func catalogRow(doc, control string) (string, bool) {
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "| `"+control+"` |") {
			return line, true
		}
	}
	return "", false
}
