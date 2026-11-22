package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// urllib3 is one scanner's finding of a urllib3 1.26.20 flaw in component, read from repo's
// requirements.txt.
func urllib3(tool, rule, component, repo string, aliases ...string) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: sarif.LevelError, Component: component, Repository: repo, Aliases: aliases,
		Location: sarif.Location{URI: "requirements.txt"},
		Package:  &sarif.Package{Name: "urllib3", Version: "1.26.20", Ecosystem: "pip", PURL: "pkg:pypi/urllib3@1.26.20"},
	}
}

// OSV-Scanner names a Python finding by the PyPA advisory it grouped first, PYSEC-2026-1994, with the
// CVE among its aliases; Trivy names the same flaw by the CVE. The alias makes them one flaw, in each
// of two repositories, and each repository counts its own.
func TestCorrelationJoinsAPyPAKeyedFindingToTheCVE(t *testing.T) {
	const pysec, cve, ghsa = "PYSEC-2026-1994", "CVE-2025-66471", "GHSA-2xpw-w6gg-jr37"
	ctrls := controlsWith(
		urllib3("osv-scanner", pysec, "api", "repo-api", ghsa, cve),
		urllib3("trivy", cve, "api", "repo-api"),
		urllib3("osv-scanner", pysec, "api", "repo-worker", ghsa, cve),
		urllib3("trivy", cve, "api", "repo-worker"),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Fatalf("groups = %d, want one flaw per repository", groups)
	}
	if got := counted(ctrls["sca"].Report.Results); len(got["api"]) != 2 {
		t.Errorf("counted = %v, want one copy counted in each repository", got)
	}
}
