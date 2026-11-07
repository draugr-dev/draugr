package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A package Grype identified inside a binary carries no purl. The same flaw in the same version in
// two files of one repository counts once, and once in each of two repositories, keyed on the
// ecosystem, name and version it does carry. A version apart, or a package missing its version, is
// not joined.
func TestABinaryPackageWithNoPurlCountsOncePerRepository(t *testing.T) {
	zip := func(repo, file, version string) sarif.Result {
		return sarif.Result{
			RuleID: "CVE-2026-48095-7-Zip", Level: sarif.LevelError, Component: "app", Repository: repo, Tool: "grype",
			Location: sarif.Location{URI: file, StartLine: 1},
			Package:  &sarif.Package{Name: "7-Zip", Version: version, Ecosystem: "binary", FixedVersion: "26.01"},
		}
	}
	results := []sarif.Result{
		zip("one", "lib/7z64.dll", "26.00"), zip("one", "lib/7zArm64.dll", "26.00"),
		zip("two", "lib/7z64.dll", "26.00"), zip("two", "lib/7zArm64.dll", "26.00"),
		zip("one", "old/7z.dll", "25.01"),
	}
	noVersion := zip("one", "x/7z.dll", "")
	results = append(results, noVersion, noVersion)
	results[len(results)-1].Location.URI = "y/7z.dll"
	ctrls := map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{Results: results}}}

	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Errorf("groups = %d, want one per repository for 26.00", groups)
	}
	counted := 0
	for _, r := range ctrls["sca"].Report.Results {
		if !r.Correlated() {
			counted++
		}
	}
	// 26.00 once in each repository, 25.01 on its own, and the two findings with no version apart.
	if counted != 5 {
		t.Errorf("counted %d findings, want 5", counted)
	}
}
