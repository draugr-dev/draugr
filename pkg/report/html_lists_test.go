package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Every release is its own phrase, and a menu offering each one is a list of versions rather than
// a question somebody asks. The row keeps the version; the menu asks whether an upgrade exists.
func TestTheFixMenuFoldsEveryReleaseIntoOneUpgrade(t *testing.T) {
	a := toHTMLFinding(finding{control: "sca", pkg: &sarif.Package{Name: "openssl", FixedVersion: "3.0.14"}})
	b := toHTMLFinding(finding{control: "sca", pkg: &sarif.Package{Name: "zlib", FixedVersion: "1.3.1"}})
	none := toHTMLFinding(finding{control: "sca", pkg: &sarif.Package{Name: "expat"}})
	if a.Fix != "upgrade to 3.0.14" || b.Fix != "upgrade to 1.3.1" {
		t.Fatalf("the row lost its version: %q, %q", a.Fix, b.Fix)
	}
	if a.FixKind != "upgrade" || b.FixKind != "upgrade" {
		t.Errorf("two releases are two menu values: %q, %q", a.FixKind, b.FixKind)
	}
	if none.FixKind != "no upgrade published" {
		t.Errorf("a finding with no release is offered as %q", none.FixKind)
	}
}

// The search box offers to find a package, and a scanner's message does not always name the
// package it is about.
func TestSearchFindsAFindingByItsPackage(t *testing.T) {
	f := toHTMLFinding(finding{ruleID: "CVE-1", control: "sca", message: "heap overflow",
		pkg: &sarif.Package{Name: "OpenSSL", FixedVersion: "3.0.14"}})
	if !strings.Contains(f.Search, "openssl") {
		t.Errorf("searching for the package misses the finding: %q", f.Search)
	}
}

// The mark says which way the band moved, so the row can say it in color as well as by glyph. A
// mark that moved nothing, a finding from history, has no direction to show.
func TestAMovedMarkCarriesItsDirection(t *testing.T) {
	for _, c := range []struct {
		name string
		f    finding
		dir  string
	}{
		{"escalated", finding{escalation: &sarif.Escalation{Signal: "kev", From: "high", To: "critical"}}, "up"},
		{"floored", finding{priorityFloor: "P2"}, "up"},
		{"unreachable", finding{reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable, RankedAs: "low"}}, "down"},
		{"historical", finding{historical: true}, ""},
	} {
		got := toHTMLFinding(c.f)
		if got.MovedDir != c.dir {
			t.Errorf("%s: direction %q, want %q", c.name, got.MovedDir, c.dir)
		}
		if got.MovedLabel == "" || got.MovedGlyph == "" {
			t.Errorf("%s: the mark rendered with nothing in it", c.name)
		}
	}
	if got := toHTMLFinding(finding{}); got.MovedLabel != "" {
		t.Errorf("a finding nothing moved carries a mark: %q", got.MovedLabel)
	}
}

// Two scanners and two fixes, because one value in a menu proves it renders and two prove the
// menu counts each rather than the set.
func TestTheStripOffersFixAndScannerAsMenus(t *testing.T) {
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Tool: "trivy", Priority: "P1",
				Package: &sarif.Package{Name: "openssl", FixedVersion: "3.0.14"}},
			{RuleID: "CVE-2", Level: sarif.LevelError, Tool: "trivy", Priority: "P2",
				Package: &sarif.Package{Name: "zlib", FixedVersion: "1.3.1"}},
		}}},
		"secrets": {Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
			{RuleID: "aws-key", Level: sarif.LevelError, Tool: "gitleaks", Priority: "P1"},
		}}},
	}}}
	page := renderHTML(t, d)
	for _, want := range []string{
		`data-fix="upgrade" data-sc="trivy"`,
		`data-fix="rotate the credential" data-sc="gitleaks"`,
		`<span class="menu-anchor" data-k="fix">`,
		`<span class="menu-anchor folded" data-k="sc">`,
		`<span class="menu-anchor folded" data-k="s">`,
		`id="narrow"`,
		`<input type="checkbox" data-k="fix" value="upgrade">upgrade</span>
        <span class="c">2</span>`,
		`<input type="checkbox" data-k="sc" value="gitleaks">gitleaks</span>
        <span class="c">1</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page is missing %q", want)
		}
	}
	// Priority and fix lead, and the rest fold behind Narrow.
	if strings.Index(page, `data-k="fix">`) > strings.Index(page, `id="narrow"`) ||
		strings.Index(page, `id="narrow"`) > strings.Index(page, `data-k="s">`) {
		t.Error("the leading menus and the folded ones are in the wrong order around Narrow")
	}
}

// The report opens on Findings, and the verdict and the tab row are pinned together, so the
// answer and the way to the rest of the report stay in view over a long list.
func TestFindingsIsTheFirstTabAndTheHeaderIsPinned(t *testing.T) {
	page := renderHTML(t, componentData())
	nav := section(t, page, `<nav class="tabs"`, `</nav>`)
	first := strings.Index(nav, `<a class="tab"`)
	if first < 0 || !strings.HasPrefix(nav[first:], `<a class="tab" href="#findings-h">Findings</a>`) {
		t.Errorf("Findings is not the first tab:\n%s", nav)
	}
	pin := section(t, page, `<div class="pin">`, `</div>
`)
	if !strings.Contains(pin, `<header class="strip">`) {
		t.Error("the verdict is not inside the pinned row")
	}
	if !strings.Contains(page, `</nav>
</div>`) {
		t.Error("the tab row is not inside the pinned row")
	}
}

// A long list is paged rather than drawn at once. The controls are in the page from the start and
// hidden, so a reader without scripts gets every row and no control that does nothing.
func TestEachListCarriesItsCountAndPaging(t *testing.T) {
	page := renderHTML(t, goldenFullData())
	for _, list := range []string{`id="work"`, `id="all"`} {
		part := section(t, page, list, `</section>`)
		for _, want := range []string{
			`<div class="listbar" hidden>`, `data-n="25"`, `data-n="50"`, `data-n="100"`,
			`<button type="button" class="next" hidden></button>`,
			`<p class="nomatch" hidden><b>Nothing here matches.</b>`,
		} {
			if !strings.Contains(part, want) {
				t.Errorf("%s is missing %q", list, want)
			}
		}
	}
	// The downloads follow the list rather than sitting above it.
	all := section(t, page, `id="all"`, `</section>`)
	if strings.Index(all, `id="findings"`) > strings.Index(all, `class="dl"`) {
		t.Error("the downloads sit above the findings")
	}
}

// An action is a row in the same panel as a finding, and its count is the way into the findings
// it clears.
func TestAnActionIsARowThatOpensItsFindings(t *testing.T) {
	page := renderHTML(t, goldenFullData())
	acts := section(t, page, `id="acts"`, `</section>`)
	for _, want := range []string{`<div class="act" data-a="`, `<span class="lbl">control</span>`, `class="act-clears"`,
		// What a rule found, under a title that only names the rule, as the console prints it.
		`<div class="sub">Detected user input flowing into a raw SQL string</div>`} {
		if !strings.Contains(acts, want) {
			t.Errorf("the action rows are missing %q", want)
		}
	}
}
