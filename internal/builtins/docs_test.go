package builtins

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/plugin"
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
			"  Every %s ships one: what it does, the tool behind it, its license and terms of\n"+
			"  use, and integration notes. Copy the shape of an existing neighbor in %s/.",
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

// termsSection matches however a doc states the license and terms of the thing it runs. The
// house style is a `- **License / terms:**` bullet; a heading is equally fine.
var termsSection = regexp.MustCompile(`(?i)licen[cs]e|terms of use`)

func TestEveryToolDocStatesItsTerms(t *testing.T) {
	// Draugr execs other people's software and reads other people's data, and the obligation that
	// comes with each is not visible from the code. It is the one fact about an integration that
	// nobody can derive later: a reader can see which binary is invoked, and cannot see whether
	// its terms permit what we are doing with it.
	//
	// Checked rather than remembered, for the same reason the colocated doc itself is: it is
	// mechanically checkable, and an integration whose terms nobody read still compiles.
	//
	// Controllers are exempt: they plan and aggregate, and run nothing. The obligation belongs to
	// the scanner that invokes the tool or calls the API.
	reg := Registry()
	for _, s := range reg.Scanners() {
		assertStatesTerms(t, "scanner", "internal/scanners", s.Info().Name)
	}
	for _, name := range SurveyorRegistry().Names() {
		assertStatesTerms(t, "surveyor", "internal/surveyors", name)
	}
}

func assertStatesTerms(t *testing.T, kind, dir, name string) {
	t.Helper()
	path := filepath.Join(repoRoot, dir, name+".md")
	body, err := os.ReadFile(path) //nolint:gosec // a path built from the registry, inside this repo
	if err != nil {
		return // the colocated-docs test already reports a missing file, and better
	}
	if !termsSection.Match(body) {
		t.Errorf("%s %q does not state the license or terms of what it runs (%s)", kind, name, path)
		t.Log("  Every integration says what it is allowed to do with the tool or data behind it.\n" +
			"  Native scanners say so too — \"native Draugr code (Apache-2.0)\" is an answer.")
	}
}

// sendsSection matches a doc's account of what leaves the machine.
var sendsSection = regexp.MustCompile(`(?im)^#+ .*(what is sent|privacy|data (sent|handling))`)

func TestDisclosingScannersDocumentWhatTheySend(t *testing.T) {
	// A scanner declaring `disclosure` sends something about a customer's systems to somebody
	// else. Its terms are not the whole question — the other half is what that party receives,
	// and whether they keep or share it.
	//
	// Triggered by the effect rather than by a list, so it applies to the next connector without
	// anyone adding it here. Declaring the effect is what makes a scanner honest; this makes the
	// declaration carry its explanation.
	for _, s := range Registry().Scanners() {
		info := s.Info()
		if !slices.ContainsFunc(info.Effects, func(e plugin.Effect) bool {
			return e.Kind == plugin.EffectDisclosure
		}) {
			continue
		}
		path := filepath.Join(repoRoot, "internal/scanners", info.Name+".md")
		body, err := os.ReadFile(path) //nolint:gosec // a path built from the registry, inside this repo
		if err != nil {
			continue
		}
		if !sendsSection.Match(body) {
			t.Errorf("scanner %q discloses to a third party but its doc has no section on what is sent (%s)", info.Name, path)
			t.Log("  Add a `## What is sent` section: the exact data that leaves, and what the\n" +
				"  receiving party's terms say about keeping or sharing it. A reader deciding\n" +
				"  whether to enable this is asking what the vendor learns, not what we send it over.")
		}
	}
}

// TestReadmeListsEveryControl keeps the README's table from describing a previous version of the
// tool.
//
// It is the page most people read and the one nobody re-reads. A control shipped and left out
// reads as a capability Draugr does not have; a control that was on a roadmap and has since
// shipped leaves the README claiming it is still coming, which is worse — the reader believes the
// thing they need is unavailable and stops looking.
func TestReadmeListsEveryControl(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Clean("../../README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readme := string(raw)

	for _, c := range Registry().Controllers() {
		name := c.Info().Name
		if !strings.Contains(readme, "| `"+name+"` |") {
			t.Errorf("the README's table of controls has no row for %q — a control that ships and "+
				"is not listed reads as one Draugr does not have", name)
		}
	}
	// The other direction: a row for something the registry does not serve promises a control
	// this build cannot run.
	for _, row := range regexp.MustCompile(`(?m)^\| `+"`"+`([a-z-]+)`+"`"+` \|`).FindAllStringSubmatch(readme, -1) {
		if _, ok := Registry().Controller(row[1]); !ok {
			t.Errorf("the README lists a control %q this build does not provide", row[1])
		}
	}
}

// TestReachabilityAnalyzersAreNotSelectableAsScanners guards the two halves of the reachability
// surface against drifting apart.
//
// A scanner declaring Reachability is enabled by config.reachability and must never be selectable
// from a control's scanner block: the two surfaces mean different things, and the scanner block
// is the one that reads as "run another tool" while this kind of tool ranks findings down. A new
// analyzer missing from the controllers list would be silently selectable both ways, and the
// descriptor accepting both is how a gate gets weakened by something that looked like a scanner.
func TestReachabilityAnalyzersAreNotSelectableAsScanners(t *testing.T) {
	for _, sc := range Registry().Scanners() {
		info := sc.Info()
		if !info.Reachability {
			continue
		}
		if !controllers.IsReachabilityAnalyzer(info.Name) {
			t.Errorf("scanner %q declares Reachability but internal/controllers does not know it", info.Name)
			t.Log("  Add it to reachabilityAnalyzers in internal/controllers/config.go, or it stays\n" +
				"  selectable from a scanner block — which is the surface that does not say what it does.")
		}
	}
}
