package report

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Trivy and Grype each count a different advisory against gjson in one go.mod, Trivy at the line
// that requires it and Grype at line 1, in each of two components on two repositories. One upgrade
// clears both, and the go.mod is one place to make it, named at the line that requires gjson.
func TestAnUpgradeNamesAFileOnceWhenTwoScannersCountInIt(t *testing.T) {
	advisory := func(tool, rule, ecosystem, component, repository string, line int) sarif.Result {
		return sarif.Result{
			Tool: tool, RuleID: rule, Level: sarif.LevelError, Priority: "P2",
			Component: component, Repository: repository,
			Location: sarif.Location{URI: "go.mod", StartLine: line},
			Package: &sarif.Package{Name: "github.com/tidwall/gjson", Version: "v1.6.5", FixedVersion: "v1.9.3",
				Ecosystem: ecosystem, PURL: "pkg:golang/github.com/tidwall/gjson@v1.6.5"},
		}
	}
	var results []sarif.Result
	for _, c := range []struct{ component, repository string }{{"api", "repo-api"}, {"worker", "repo-worker"}} {
		results = append(results,
			// Grype first, so the file's first finding is the one at line 1.
			advisory("grype", "GHSA-ppj4-w6xc-j3jr-github.com/tidwall/gjson", "go-module", c.component, c.repository, 1),
			advisory("trivy", "CVE-2021-42836", "gomod", c.component, c.repository, 5),
		)
	}
	got := ActionsFor(map[string]sarif.Report{"sca": {Results: results}})
	if len(got) != 2 {
		t.Fatalf("actions = %+v, want one upgrade per component", got)
	}
	for _, a := range got {
		want := []ActionLocation{{Repository: "repo-" + a.Component, Path: "go.mod", Line: 5, Kind: "manifest"}}
		if !reflect.DeepEqual(a.Locations, want) {
			t.Errorf("%s: locations = %+v, want %+v", a.Component, a.Locations, want)
		}
		if !reflect.DeepEqual(a.Where, []string{"go.mod:5"}) {
			t.Errorf("%s: where = %q, want go.mod:5 once", a.Component, a.Where)
		}
		if a.Clears != 2 {
			t.Errorf("%s: clears %d, want both advisories", a.Component, a.Clears)
		}
	}
}

// Every line a scanner writes for a file is 1: the file is named once, at its first finding.
func TestOnePerFileKeepsTheFirstWhereNoLineIsDeclared(t *testing.T) {
	fs := []finding{
		{tool: "grype", repository: "r", location: "go.mod:1"},
		{tool: "osv", repository: "r", location: "go.mod:1"},
		{tool: "trivy", repository: "r", location: "tools/go.mod:7"},
		{tool: "grype", repository: "s", location: "go.mod"},
	}
	got := onePerFile(fs)
	if len(got) != 3 || got[0].tool != "grype" || got[1].location != "tools/go.mod:7" || got[2].repository != "s" {
		t.Errorf("onePerFile = %+v", got)
	}
}
