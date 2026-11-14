package engine

import (
	"context"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// inventoryScanner lists the packages of the component it scanned, the way a dependency scan does:
// one finding, in `<component>-dep`, and an inventory holding that package, `evil` in two lockfiles
// and `fine`.
type inventoryScanner struct{}

func (inventoryScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "pkgs"} }

func (inventoryScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	c := target.Identity()
	dep := "pkg:npm/" + c + "-dep@1.0.0"
	repo := "https://example.com/" + c
	return sarif.Report{
		Tool: "pkgs",
		Results: []sarif.Result{{
			RuleID: "CVE-1", Level: sarif.LevelWarning, Repository: repo,
			Location: sarif.Location{URI: "package-lock.json", StartLine: 3},
			Package:  &sarif.Package{Name: c + "-dep", Version: "1.0.0", PURL: dep},
		}},
		Inventory: []sarif.InventoryPackage{
			{PURL: dep, Scanner: "pkgs", Repository: repo, Path: "package-lock.json", Line: 3},
			{PURL: "pkg:npm/evil@6.6.6", Scanner: "pkgs", Repository: repo, Path: "package-lock.json", Line: 9},
			{PURL: "pkg:npm/evil@6.6.6", Scanner: "pkgs", Repository: repo, Path: "tools/package-lock.json", Line: 4},
			{PURL: "pkg:npm/fine@1.0.0", Scanner: "pkgs", Repository: repo, Path: "package-lock.json", Line: 12},
		},
	}, nil
}

// maliciousRun scans two components whose lookup knows the packages given, and returns the sca
// control's findings and what the lookup was asked.
func maliciousRun(t *testing.T, known map[string]dephealth.Package) ([]sarif.Result, map[string]sarif.Rule, []string) {
	t.Helper()
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "sca", scope: plugin.ScopeComponent, scanner: "pkgs"})
	reg.RegisterScanner(inventoryScanner{})
	m := saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{{Name: "api"}, {Name: "web"}},
	}
	src := dephealth.New(nil, "")
	var asked []string
	resolve := func(_ context.Context, purls []string) error {
		asked = purls
		src.Load(known, "2026-11-14")
		return nil
	}
	res, err := New(reg, WithDependencyHealth(resolve, src)).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	return res.Controls["sca"].Report.Results, res.Controls["sca"].Report.Rules, asked
}

var flaggedMalicious = dephealth.Package{Findings: []dephealth.Finding{{Kind: dephealth.KindMalicious}}}

// The lookup asks about every package a scan listed, not only the ones a finding names: `evil` and
// `fine` carry no finding and are asked about all the same.
func TestDependencyHealthAsksAboutEveryListedPackage(t *testing.T) {
	_, _, asked := maliciousRun(t, map[string]dephealth.Package{"pkg:npm/fine@1.0.0": {}})
	want := []string{"pkg:npm/api-dep@1.0.0", "pkg:npm/evil@6.6.6", "pkg:npm/fine@1.0.0", "pkg:npm/web-dep@1.0.0"}
	if !slices.Equal(asked, want) {
		t.Errorf("asked about %v, want %v", asked, want)
	}
}

// A listed package flagged as malicious with no finding is reported, once for each component,
// repository and file it is declared in. A flagged package a finding already names is not reported
// a second time, and an unflagged one is not reported at all.
func TestAMaliciousPackageWithNoFindingIsReported(t *testing.T) {
	results, rules, _ := maliciousRun(t, map[string]dephealth.Package{
		"pkg:npm/evil@6.6.6":    flaggedMalicious,
		"pkg:npm/web-dep@1.0.0": flaggedMalicious,
		"pkg:npm/fine@1.0.0":    {},
		"pkg:npm/api-dep@1.0.0": {},
	})
	type at struct {
		component, repository, path string
		line                        int
	}
	var got []at
	for _, r := range results {
		if r.RuleID != MaliciousPackageRule {
			continue
		}
		got = append(got, at{r.Component, r.Repository, r.Location.URI, r.Location.StartLine})
		if r.Tool != MaliciousPackageTool || r.Control != "sca" || r.Message != "evil 6.6.6 is flagged as malicious" {
			t.Errorf("finding names the wrong source, control or package: %+v", r)
		}
		if r.Package == nil || r.Package.PURL != "pkg:npm/evil@6.6.6" || r.Package.Name != "evil" ||
			r.Package.Version != "6.6.6" || r.Package.Ecosystem != "npm" {
			t.Errorf("finding does not carry its package: %+v", r.Package)
		}
	}
	slices.SortFunc(got, func(a, b at) int {
		if a.component+a.path < b.component+b.path {
			return -1
		}
		return 1
	})
	want := []at{
		{"api", "https://example.com/api", "package-lock.json", 9},
		{"api", "https://example.com/api", "tools/package-lock.json", 4},
		{"web", "https://example.com/web", "package-lock.json", 9},
		{"web", "https://example.com/web", "tools/package-lock.json", 4},
	}
	if !slices.Equal(got, want) {
		t.Errorf("malicious-package findings at %v, want %v", got, want)
	}
	if _, ok := rules[MaliciousPackageRule]; !ok {
		t.Error("the report does not explain the rule its findings name")
	}
	if n := len(results); n != 2+len(want) {
		t.Errorf("%d findings, want the two scanner findings and %d added", n, len(want))
	}
}

// Nothing is added where the lookup flagged nothing.
func TestNoMaliciousPackageNoFinding(t *testing.T) {
	results, rules, _ := maliciousRun(t, map[string]dephealth.Package{"pkg:npm/fine@1.0.0": {}})
	if len(results) != 2 {
		t.Errorf("%d findings, want only the scanners' two: %+v", len(results), results)
	}
	if _, ok := rules[MaliciousPackageRule]; ok {
		t.Error("the rule was added with no finding to explain")
	}
}

func TestPurlNameVersion(t *testing.T) {
	for purl, want := range map[string][2]string{
		"pkg:npm/%40scope/name@1.2.0":                 {"@scope/name", "1.2.0"},
		"pkg:npm/left-pad@1.3.0?vcs_url=x#sub":        {"left-pad", "1.3.0"},
		"pkg:maven/org.example/lib@2.0":               {"org.example/lib", "2.0"},
		"pkg:golang/github.com/a/b@v1.0.0%2Bincompat": {"github.com/a/b", "v1.0.0+incompat"},
		"pkg:pypi/noversion":                          {"noversion", ""},
	} {
		name, version := purlNameVersion(purl)
		if name != want[0] || version != want[1] {
			t.Errorf("purlNameVersion(%q) = %q, %q, want %q, %q", purl, name, version, want[0], want[1])
		}
	}
}
