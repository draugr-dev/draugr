package report

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// importedTrivy reads the SARIF Trivy 0.76.1 wrote about a project pinning lodash 4.17.15 and
// golang.org/x/text v0.3.5, as the import scanner does, once for each component in its repository.
func importedTrivy(t *testing.T, owners ...[2]string) []sarif.Result {
	t.Helper()
	data, err := os.ReadFile("../../internal/scanners/testdata/sarif-import/trivy-deps.sarif")
	if err != nil {
		t.Fatal(err)
	}
	var out []sarif.Result
	for _, o := range owners {
		rep, _, err := sarif.FromForeignSARIF(data, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rep.Results {
			r.Scanner, r.Component, r.Repository, r.Priority = plugin.ImportScanner, o[0], o[1], "P2"
			out = append(out, r)
		}
	}
	return out
}

// Trivy's file names the package, the installed version and the fix only in each result's message.
// Read from there, its ten findings over two packages become one upgrade per package in each of two
// components, each to the release that clears every finding in it, rather than ten "Fix CVE-…" rows
// per component with no version to move to.
func TestAnImportedTrivyFileGroupsIntoUpgradesPerComponent(t *testing.T) {
	got := ActionsFor(map[string]sarif.Report{"sca": {Results: importedTrivy(t, [2]string{"api", "repo-api"}, [2]string{"web", "repo-web"})}})
	type upgrade struct{ component, pkg, from, target string }
	want := map[upgrade]int{
		{"api", "lodash", "4.17.15", "4.18.0"}:            6,
		{"api", "golang.org/x/text", "v0.3.5", "v0.41.0"}: 4,
		{"web", "lodash", "4.17.15", "4.18.0"}:            6,
		{"web", "golang.org/x/text", "v0.3.5", "v0.41.0"}: 4,
	}
	if len(got) != len(want) {
		t.Fatalf("actions = %+v, want an upgrade of each package in each component", got)
	}
	for _, a := range got {
		u := upgrade{a.Component, a.Package, a.From, a.Target}
		if clears, ok := want[u]; !ok || a.Clears != clears || !strings.HasPrefix(a.Title, "Upgrade ") {
			t.Errorf("action %q %+v clears %d, want one of %v", a.Title, u, a.Clears, want)
		}
	}
}

// A run says once how many imported findings about a vulnerability name no CVE, which KEV and EPSS
// cannot be asked about. A finding naming one by an alias, a finding Draugr's own scanner reported
// and a code finding imported with no package are not among them.
func TestARunSaysHowManyImportedFindingsNameNoCVE(t *testing.T) {
	imported := func(rule string, pkg *sarif.Package, aliases ...string) sarif.Result {
		return sarif.Result{Tool: "Grype", Scanner: plugin.ImportScanner, RuleID: rule, Level: sarif.LevelError,
			Priority: "P2", Component: "api", Repository: "repo-api", Package: pkg, Aliases: aliases}
	}
	lodash := &sarif.Package{Name: "lodash", Version: "4.17.15", FixedVersion: "4.17.21"}
	results := []sarif.Result{
		imported("GHSA-35jh-r3h4-6jhm-lodash", lodash),
		imported("GHSA-p6mc-m468-83gw-lodash", lodash),
		imported("SNYK-JS-MULTER-10773732", &sarif.Package{Name: "multer", Version: "2.0.1"}),
		imported("GHSA-29mw-wpgm-hmr9-lodash", lodash, "CVE-2020-28500"),
		imported("B602", nil),
		{Tool: "grype", Scanner: "grype-fs", RuleID: "GHSA-xxjr-mmjv-4gpg", Priority: "P2", Package: lodash},
	}
	const note = "not checked against KEV or EPSS: 3 imported findings name no CVE"

	d := kevData(results)
	if _, notes := signals(d, summarize(d)); len(notes) != 1 || notes[0] != note {
		t.Errorf("notes = %q, want %q", notes, note)
	}
	for _, view := range []View{"", ViewCompact} {
		d.View = view
		var b bytes.Buffer
		if err := (consoleReporter{}).Render(&b, d); err != nil {
			t.Fatal(err)
		}
		if strings.Count(b.String(), note) != 1 {
			t.Errorf("view %q: want the note once:\n%s", view, b.String())
		}
	}
	d.View = ""
	var md bytes.Buffer
	if err := (markdownReporter{}).Render(&md, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "_"+note+"_") {
		t.Errorf("markdown: want the note:\n%s", md.String())
	}

	d = kevData(results[:1])
	if _, notes := signals(d, summarize(d)); len(notes) != 1 || !strings.HasSuffix(notes[0], ": 1 imported finding names no CVE") {
		t.Errorf("notes = %q, want one finding counted", notes)
	}
	// A run that neither read KEV nor holds a finding it could list has no KEV row to qualify, and
	// says nothing either dataset was not asked.
	d.Exploitability = nil
	if rows, notes := signals(d, summarize(d)); len(rows) != 0 || len(notes) != 0 {
		t.Errorf("rows = %+v, notes = %q, want neither", rows, notes)
	}
	// Nor does a run with nothing imported.
	d = kevData(results[5:])
	if _, notes := signals(d, summarize(d)); len(notes) != 0 {
		t.Errorf("notes = %q, want none", notes)
	}
}
