package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// statesData is a change that touches a finding in every state `draugr diff` reports, on two
// components: api gains a finding, has one fixed and accepts one; web's exclusion is removed, and it
// keeps one finding as it was and one still excused.
func statesData() report.Data {
	excused := func(r sarif.Result) sarif.Result {
		r.Suppression = &sarif.Suppression{Kind: "external", Justification: "not reachable from a request"}
		return r
	}
	fixed := changeResult("sca", "trivy", "CVE-2019-10906", "api", goldenAPIRepo, "requirements.txt", 5, "P1",
		"str.format_map allows sandbox escape", nil)
	accepting := changeResult("sca", "trivy", "CVE-2020-1747", "api", goldenAPIRepo, "requirements.txt", 4, "P1",
		"Arbitrary command execution through python/object/new", nil)
	unaccepting := changeResult("sca", "trivy", "CVE-2018-1000656", "web", goldenWebRepo, "requirements.txt", 2, "P1",
		"Denial of service via crafted JSON", nil)
	unchanged := changeResult("sast", "semgrep", "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
		"web", goldenWebRepo, "app/db.py", 42, "P2", "Detected user input flowing into a raw SQL string", nil)
	still := changeResult("sca", "trivy", "CVE-2026-27205", "web", goldenWebRepo, "requirements.txt", 1, "P3",
		"Information disclosure via improper caching of session data", nil)
	added := changeResult("sca", "trivy", "CVE-2025-66418", "api", goldenAPIRepo, "requirements.txt", 6, "P2",
		"Unbounded decompression chain leads to resource exhaustion", urllib3("2.6.0"))

	base := []sarif.Result{fixed, accepting, excused(unaccepting), unchanged, excused(still)}
	head := []sarif.Result{excused(accepting), unaccepting, unchanged, excused(still), added}
	baseReport := sarif.Report{Results: base, Provenance: []sarif.Provenance{
		{Tool: "trivy-fs", Fields: []sarif.Field{{Key: "repository", Value: goldenAPIRepo}, {Key: "revision", Value: "4f2a9c1e0b3d"}}},
		{Tool: "trivy-fs", Fields: []sarif.Field{{Key: "repository", Value: goldenWebRepo}, {Key: "revision", Value: "9d8e7f6a5b4c"}}},
	}}
	compared := diff.Compare(baseReport, sarif.Report{Results: head})
	compared.Gate = diff.Gate{FailOnPriority: "P2"}
	compared.Tripped = compared.GateNew("", "P2")

	byControl := map[string][]sarif.Result{}
	for _, r := range head {
		byControl[r.Control] = append(byControl[r.Control], r)
	}
	return report.Data{
		Project: "acme",
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"sca":  {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: byControl["sca"]}},
			"sast": {Control: "sast", Report: sarif.Report{Tool: "semgrep", Results: byControl["sast"]}},
		}},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "sast", Verdict: norn.Fail}, {Control: "sca", Verdict: norn.Fail},
		}},
		Components: []report.ComponentVerdict{{Name: "api", Verdict: norn.Fail}, {Name: "web", Verdict: norn.Fail}},
		Gate: report.GateSettings{
			FailOnNew: "P2",
			New: &skald.NewFindings{
				Base:       sarif.RepositoriesIn([]sarif.Report{baseReport}),
				Introduced: compared.Counted().New,
				Tripped:    compared.Tripped,
			},
		},
		Change: diff.ScanView{Result: compared},
	}
}

// renderAs renders d in the named format.
func renderAs(t *testing.T, format string, d report.Data) string {
	t.Helper()
	r, err := report.For(format)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.Render(&b, d); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A run judged on its change shows everything that changed against the base, as `draugr diff` does: new,
// unaccepted, accepted and fixed, then what the change left as it was. The accepted and fixed
// findings are listed in the Change section, since no other section lists them as the change's, and a
// finding whose acceptance ended is marked where Findings lists it.
func TestADiffReportShowsEveryStateAgainstTheBase(t *testing.T) {
	d := statesData()
	if got := d.Change.States(); len(got.New) != 1 || len(got.Fixed) != 1 || len(got.Accepted) != 1 ||
		len(got.Unaccepted) != 1 || len(got.Unchanged) != 1 || len(got.StillAccepted) != 1 || !got.Changed() {
		t.Fatalf("states = %+v, want one finding in each", got)
	}

	md := renderAs(t, "markdown", d)
	for _, want := range []string{
		"| + new | 1 | 1 P2 |",
		"| ! unaccepted | 1 | 1 P1 |",
		"| ~ accepted | 1 | 1 P1 |",
		"| - fixed | 1 | 1 P1 |",
		"| unchanged | 1 | 1 P2 |",
		"| still accepted | 1 | 1 P3 |",
		// The action that clears the unaccepted finding is part of what the change asks for.
		"· 1 unaccepted",
		"**~ Accepted**",
		"| P1 | CVE-2020-1747 | api | requirements.txt:4 |",
		"**- Fixed**",
		"| P1 | CVE-2019-10906 | api | requirements.txt:5 |",
		"| Control | Gate | + new | ! unaccepted | ~ accepted | - fixed |",
		"| sca | **FAIL** | 1 P2 | 1 P1 | 1 P1 | 1 P1 |",
		"| api | **FAIL** | 1 P2 |  | 1 P1 | 1 P1 |",
		"| web | pass |  | 1 P1 |  |  |",
		"| ! unaccepted | P1 |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}

	html := renderAs(t, "html", d)
	for _, want := range []string{
		`data-state="unaccepted" data-title="unaccepted since 4f2a9c1, 9d8e7f6">1</a>`,
		// Every count is a way to its findings: fixed and accepted into Findings, still accepted to
		// the Accepted section that holds it.
		`data-state="fixed" data-title="fixed since 4f2a9c1, 9d8e7f6">1</a>`,
		`data-state="accepted" data-title="accepted since 4f2a9c1, 9d8e7f6">1</a>`,
		`<a href="#suppressed">1</a>`,
		`data-change="unaccepted"`,
		`data-change="fixed"`,
		`data-change="accepted"`,
		// The definitions sit behind one mark, not beside each row.
		`<dialog id="state-defs" class="defs">`,
		// An accepted finding says why, for the reviewer asked to approve it.
		`<span class="lbl">accepted</span> not reachable from a request`,
		// A fixed finding's band is outlined.
		`<span class="pri P1 gone">P1</span>`,
		// A fix is not work, so its counts do not wear a band's fill.
		`<span class="sev plain">1 P1</span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML lacks %s", want)
		}
	}
	// The gloss a row once carried, which the definitions behind the mark now say instead.
	if strings.Contains(html, "excused since the base") {
		t.Error("a state is explained inline")
	}
}
