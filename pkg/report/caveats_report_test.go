package report

import (
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// everyCaveatData is a run holding one caveat of each kind across two components, under a gate
// that fails on one of them. The console, the HTML report and the markdown report all render it,
// so a caveat any of them drops fails a test.
func everyCaveatData() Data {
	d := Data{
		Project:           "caveats",
		FailOnCaveats:     []saga.CaveatKind{saga.CaveatUnboundImports},
		FailOnCaveatsFrom: "config.gate.failOnCaveats",
		Uncovered:         []Gap{{Component: "edge", Surface: "hosts", Controls: []string{"dast", "headers", "tls"}}},
		Run: engine.Result{
			Controls: map[string]plugin.ControlResult{
				"sca": {Control: "sca", Report: sarif.Report{Provenance: []sarif.Provenance{{
					Tool: plugin.ImportScanner, Fields: []sarif.Field{
						{Key: "file", Value: "reports/review.sarif"}, {Key: "commit", Value: "not stated"},
						{Key: "component", Value: "ledger"}}}}}},
			},
			Skipped: []engine.SkippedJob{{Control: "kubernetes", Scanner: "kube-bench", Component: "edge",
				Reason: "audits the whole cluster and cannot be narrowed to namespace edge"}},
			UnreadChecks: []engine.UnreadChecks{{Component: "edge", Control: "cloud", Group: "compute",
				Checks: []string{"compute_instance_public_ip"}, Reason: "denied compute.instances.list"}},
			Inputs: []engine.InputCoverage{{Component: "ledger", Control: "sca", Scanners: []string{"trivy-fs"},
				Unread: []engine.UnreadInput{{Repository: "./ledger", Path: "package.json", Reason: "no lockfile"}}}},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{{Control: "sca", Verdict: norn.Pass}}},
		Components: []ComponentVerdict{
			{Name: "edge", Verdict: norn.Pass, Exposure: "public", Criticality: "critical"},
			{Name: "ledger", Verdict: norn.Pass, Exposure: "internal", Criticality: "critical"},
		},
	}
	d.Components[1].FailedCaveats = FailedCaveats(d)
	return d
}

// everyCaveat is what everyCaveatData holds, written out rather than read back from caveats(), so a
// kind the shared list stops gathering fails here too.
var everyCaveat = []struct {
	component, kind, what, why string
	fails                      bool
}{
	{"edge", "not-checked", "hosts", "dast, headers, tls off", false},
	{"edge", "not-measured", "kube-bench", "audits the whole cluster and cannot be narrowed to namespace edge", false},
	{"edge", "unread-checks", "compute", "1 check · denied compute.instances.list", false},
	{"ledger", "unbound-imports", "reports/review.sarif", "names no commit, so nothing ties its findings to this code", true},
	{"ledger", "unread-files", "package.json", "no lockfile (sca)", false},
}

// caveatsSection is the HTML report's Caveats section, from its heading to the end of its panel.
func caveatsSection(t *testing.T, doc string) string {
	t.Helper()
	return section(t, doc, `<summary id="caveats">`, `</details>`)
}

// Every caveat the console lists is in the HTML and the markdown report, with its kind, what it
// names and why, under its own component.
func TestEveryCaveatIsInEveryReport(t *testing.T) {
	d := everyCaveatData()
	console := renderWith(t, consoleReporter{}, d)
	html := caveatsSection(t, renderHTML(t, d))
	md := renderWith(t, markdownReporter{}, d)

	edge := section(t, html, `<span class="cv-comp">edge</span>`, `<span class="cv-comp">ledger</span>`)
	ledger := section(t, html, `<span class="cv-comp">ledger</span>`, `</details>`)
	mdEdge := section(t, md, "**edge**", "**ledger**")
	mdLedger := section(t, md, "**ledger**", "\n\n#")
	for _, c := range everyCaveat {
		mark := "  "
		if c.fails {
			mark = "✗ "
		}
		row := regexp.MustCompile(`(?m)^  ` + c.component + `\s+` + regexp.QuoteMeta(c.what) + `\s+` +
			regexp.QuoteMeta(mark+c.kind) + `\s+` + regexp.QuoteMeta(c.why) + `$`)
		if !row.MatchString(console) {
			t.Errorf("the console has no row for %s %s:\n%s", c.component, c.what, console)
		}

		chip := `<span class="cvchip">` + c.kind + `</span>`
		if c.fails {
			chip = `<span class="cvchip fails">✗ ` + c.kind + `</span>`
		}
		htmlRow := `<span class="chips">` + chip + "</span>\n" +
			`  <div class="what"><div class="rule"><span class="name">` + c.what + `</span></div><div class="sub">` + c.why + `</div></div>`
		group, other := edge, ledger
		mdGroup, mdOther := mdEdge, mdLedger
		if c.component == "ledger" {
			group, other, mdGroup, mdOther = ledger, edge, mdLedger, mdEdge
		}
		if !strings.Contains(group, htmlRow) || strings.Contains(other, c.what) {
			t.Errorf("the HTML report does not list %s under %s alone:\n%s", c.what, c.component, html)
		}

		kind := "`" + c.kind + "`"
		if c.fails {
			kind = "✗ " + kind
		}
		mdRow := "- " + kind + " · `" + c.what + "` · " + c.why + "\n"
		if !strings.Contains(mdGroup, mdRow) || strings.Contains(mdOther, c.what) {
			t.Errorf("the markdown report does not list %q under %s alone:\n%s", mdRow, c.component, md)
		}
	}
}

// A caveat the gate fails on turns the tab to the fail color and is the one row marked, and the
// note names the setting that made it fail.
func TestACaveatTheGateFailsOnIsMarkedInTheReports(t *testing.T) {
	d := everyCaveatData()
	doc := renderHTML(t, d)
	if !strings.Contains(doc, `<a class="tab err" href="#caveats">Caveats</a>`) {
		t.Error("the Caveats tab does not wear the fail color while a caveat fails the run")
	}
	html := caveatsSection(t, doc)
	if !strings.Contains(html, `<span class="cv-key"><span class="cv-x">✗</span>fails the run · <code>config.gate.failOnCaveats: unbound-imports</code></span>`) {
		t.Errorf("the note does not say what fails the run:\n%s", html)
	}
	rows := section(t, html, `<div class="rows">`, `</details>`)
	if n := strings.Count(rows, "✗"); n != 1 || !strings.Contains(rows, `<span class="cvchip fails">✗ unbound-imports</span>`) {
		t.Errorf("want the mark on the unbound import alone, got %d marks:\n%s", n, rows)
	}
	// The component's row from the Components table, so the ERROR there and the caveat behind it
	// are read together.
	for _, want := range []string{
		`<span class="cv-comp">edge</span><span class="cls">public · critical</span><span class="cv-verdict"><span class="ok">PASS</span></span>`,
		`<span class="cv-comp">ledger</span><span class="cls">internal · critical</span><span class="cv-verdict"><span class="err">ERROR</span></span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing the group header %s:\n%s", want, html)
		}
	}
	// After Components and before Errors, in the tab row and in the page.
	if strings.Index(doc, `href="#components"`) > strings.Index(doc, `href="#caveats"`) ||
		strings.Index(doc, `<summary id="components">`) > strings.Index(doc, `<summary id="caveats">`) {
		t.Error("Caveats does not follow Components")
	}

	md := renderWith(t, markdownReporter{}, d)
	for _, want := range []string{
		"### Caveats\n\nShortfalls in what the run covered, by component.\n\n",
		"✗ fails the run · `config.gate.failOnCaveats: unbound-imports`\n",
		"**edge** · public · critical · pass\n",
		"**ledger** · internal · critical · **ERROR**\n",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown is missing %q:\n%s", want, md)
		}
	}
	if strings.Index(md, "### Components") > strings.Index(md, "### Caveats") {
		t.Errorf("markdown lists Caveats before Components:\n%s", md)
	}
}

// Accepted by --allow-scan-errors, the run passed: the tab and the marks leave the fail color, and
// the note says what accepted them, as the console's heading does.
func TestAcceptedCaveatsLeaveTheFailColor(t *testing.T) {
	d := everyCaveatData()
	d.AcceptedErrors = true
	d.Verdict.Verdict = norn.Pass
	doc := renderHTML(t, d)
	if !strings.Contains(doc, `<a class="tab" href="#caveats">Caveats</a>`) {
		t.Error("the Caveats tab wears the fail color for a caveat that was accepted")
	}
	html := caveatsSection(t, doc)
	for _, want := range []string{
		`<span class="cv-key accepted"><span class="cv-x">✗</span>would fail the run, accepted by <code>--allow-scan-errors</code> · <code>config.gate.failOnCaveats: unbound-imports</code></span>`,
		`<span class="cvchip accepted">✗ unbound-imports</span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s:\n%s", want, html)
		}
	}
	if strings.Contains(html, "✗</span>fails the run") || strings.Contains(html, "cvchip fails") {
		t.Errorf("an accepted caveat reads as failing:\n%s", html)
	}
	md := renderWith(t, markdownReporter{}, d)
	if !strings.Contains(md, "✗ would fail the run, accepted by `--allow-scan-errors` · `config.gate.failOnCaveats: unbound-imports`\n") ||
		strings.Contains(md, "✗ fails the run") {
		t.Errorf("markdown does not say the caveat was accepted:\n%s", md)
	}
}

// With no kind the gate fails on, nothing is marked, the tab keeps its color, and the note names
// the setting that would, as the console's heading does.
func TestCaveatsNothingFailsOnNameTheSetting(t *testing.T) {
	d := everyCaveatData()
	d.FailOnCaveats, d.FailOnCaveatsFrom = nil, ""
	d.Components[1].FailedCaveats = nil
	doc := renderHTML(t, d)
	html := caveatsSection(t, doc)
	if !strings.Contains(doc, `<a class="tab" href="#caveats">Caveats</a>`) || strings.Contains(html, "✗") {
		t.Errorf("a caveat is marked failing with nothing in the gate:\n%s", html)
	}
	if !strings.Contains(html, `<span class="cv-key">No caveat fails the run · <code>config.gate.failOnCaveats</code> lists the kinds that do</span>`) {
		t.Errorf("the note does not name the setting:\n%s", html)
	}
	md := renderWith(t, markdownReporter{}, d)
	if !strings.Contains(md, "No caveat fails the run · `config.gate.failOnCaveats` lists the kinds that do\n") || strings.Contains(md, "✗") {
		t.Errorf("markdown:\n%s", md)
	}
}

// A run with no caveats has no tab and no section, in either report.
func TestARunWithNoCaveatsHasNoCaveatsSection(t *testing.T) {
	d := everyCaveatData()
	d.Uncovered, d.Run.Skipped, d.Run.UnreadChecks, d.Run.Inputs = nil, nil, nil, nil
	d.Run.Controls = map[string]plugin.ControlResult{"sca": {Control: "sca"}}
	d.Components[1].FailedCaveats = nil
	doc := renderHTML(t, d)
	if strings.Contains(doc, `href="#caveats"`) || strings.Contains(doc, `id="caveats"`) {
		t.Error("the HTML report carries a Caveats tab or section for a run with none")
	}
	if md := renderWith(t, markdownReporter{}, d); strings.Contains(md, "Caveats") {
		t.Errorf("the markdown report carries a Caveats section for a run with none:\n%s", md)
	}
}

// A run of one component has no breakdown, so a group is headed by the name alone. A component the
// scope left out reads as the Components table reads it.
func TestACaveatGroupWithoutABreakdownIsHeadedByItsName(t *testing.T) {
	d := everyCaveatData()
	d.Components = nil
	html := caveatsSection(t, renderHTML(t, d))
	if !strings.Contains(html, `<div class="cv-head"><span class="cv-comp">edge</span></div>`) {
		t.Errorf("want the name alone:\n%s", html)
	}
	if md := renderWith(t, markdownReporter{}, d); !strings.Contains(md, "\n**edge**\n") {
		t.Errorf("want the name alone in markdown:\n%s", md)
	}

	d.Scope = &Scope{SkippedComponents: []string{"edge"}}
	d.Components = []ComponentVerdict{{Name: "ledger", Verdict: norn.Fail}}
	if html := caveatsSection(t, renderHTML(t, d)); !strings.Contains(html,
		`<span class="cv-comp">edge</span><span class="cv-verdict"><span class="none">not scanned</span></span>`) ||
		!strings.Contains(html, `<span class="cv-comp">ledger</span><span class="cv-verdict"><span class="err">FAIL</span></span>`) {
		t.Errorf("want edge not scanned and ledger failing:\n%s", html)
	}
	if md := renderWith(t, markdownReporter{}, d); !strings.Contains(md, "\n**ledger** · **FAIL**\n") {
		t.Errorf("want ledger failing in markdown:\n%s", md)
	}
}

// A caveat no component claims is grouped apart, under a header that says so.
func TestACaveatWithNoComponentIsGroupedApart(t *testing.T) {
	d := everyCaveatData()
	d.Uncovered[0].Component = ""
	if html := caveatsSection(t, renderHTML(t, d)); !strings.Contains(html, `<span class="cv-comp"><span class="none">no component</span></span>`) {
		t.Errorf("want a group for no component:\n%s", html)
	}
	if md := renderWith(t, markdownReporter{}, d); !strings.Contains(md, "\n_no component_\n\n- `not-checked` · `hosts`") {
		t.Errorf("want a group for no component in markdown:\n%s", md)
	}
}
