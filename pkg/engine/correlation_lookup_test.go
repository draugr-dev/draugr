package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// corazaCopy is one imported file's finding of a github.com/corazawaf/coraza/v3 advisory in repo,
// keyed on rule as the file names it, at priority.
func corazaCopy(tool, format, rule, repo, priority string, lookup *sarif.CVELookup) sarif.Result {
	return sarif.Result{
		Tool: tool, Scanner: sarif.ImportScanner, ImportFormat: format, RuleID: rule, Level: sarif.LevelError,
		Component: "waf", Repository: repo, Priority: priority, CVELookup: lookup,
		Location: sarif.Location{URI: "go.mod", StartLine: 7},
		Package: &sarif.Package{Name: "github.com/corazawaf/coraza/v3", Version: "v3.3.0", FixedVersion: "v3.3.3",
			Ecosystem: "gomod", PURL: "pkg:golang/github.com/corazawaf/coraza/v3@v3.3.0"},
	}
}

// govulndbLookup is the Go vulnerability database's answer for a finding named by id: the record
// that lists it, and that record's CVEs.
func govulndbLookup(id string, cves ...string) *sarif.CVELookup {
	return &sarif.CVELookup{CVEs: cves, ID: id, Record: "GO-2026-7001", Dataset: "govulndb", AsOf: "2026-11-23"}
}

// govulncheck's imported file names a coraza advisory only by its GitHub advisory id, and Trivy's
// imported SARIF names the same flaw by its CVE with no other id beside it. Where the Go
// vulnerability database's record lists both, the two are one flaw, counted once in each of two
// repositories with the other file's copy behind it. Without a lookup, nothing says they are one,
// and both stay, as before.
func TestCorrelationJoinsAGHSAOnlyCopyThroughTheLookedUpCVE(t *testing.T) {
	const ghsa, cve = "GHSA-3c6w-j9xm-8h2h", "CVE-2026-107833"
	build := func(lookup bool) []sarif.Result {
		var results []sarif.Result
		for _, repo := range []string{"repo-waf", "repo-edge"} {
			var l *sarif.CVELookup
			if lookup {
				l = govulndbLookup(ghsa, cve)
			}
			results = append(results,
				corazaCopy("govulncheck", "govulncheck-json", ghsa, repo, "P2", l),
				corazaCopy("Trivy", "sarif", cve, repo, "P2", nil))
		}
		return results
	}

	ctrls := controlsWith(build(true)...)
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Fatalf("groups = %d, want one per repository", groups)
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 2 {
		t.Errorf("counted %d, want the flaw once in each repository", n)
	}
	for _, r := range ctrls["sca"].Report.Results {
		if !r.Correlated() && (r.Correlation == nil || len(r.Correlation.AlsoFoundBy) != 1) {
			t.Errorf("%s %s in %s: correlation %+v, want the other file's copy behind it", r.Tool, r.RuleID, r.Repository, r.Correlation)
		}
	}

	// No current copy of the database: nothing was looked up, and both copies count.
	ctrls = controlsWith(build(false)...)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d without a lookup, want none", groups)
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 4 {
		t.Errorf("counted %d without a lookup, want both copies in both repositories", n)
	}
}

// A record listing two CVEs says the GitHub advisory is both of them, and Trivy reports each CVE as a
// finding of its own. Joining the GitHub advisory's copy on either would fold Trivy's two findings
// into one, so it joins neither, and all three count.
func TestCorrelationDoesNotJoinThroughARecordWithTwoCVEs(t *testing.T) {
	const ghsa = "GHSA-3c6w-j9xm-8h2h"
	ctrls := controlsWith(
		corazaCopy("govulncheck", "govulncheck-json", ghsa, "repo-waf", "P2", govulndbLookup(ghsa, "CVE-2026-107833", "CVE-2026-107834")),
		corazaCopy("Trivy", "sarif", "CVE-2026-107833", "repo-waf", "P2", nil),
		corazaCopy("Trivy", "sarif", "CVE-2026-107834", "repo-waf", "P2", nil),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none through a record listing two CVEs", groups)
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 3 {
		t.Errorf("counted %d, want all three", n)
	}
}

// Joined through the lookup, the flaw is counted under its higher band, whichever file's copy holds
// it: joining never ranks a flaw lower than either copy ranked it alone.
func TestCorrelationThroughALookupCountsTheHigherBand(t *testing.T) {
	const ghsa, cve = "GHSA-3c6w-j9xm-8h2h", "CVE-2026-107833"
	for _, tc := range []struct{ govulncheck, trivy string }{{"P3", "P1"}, {"P1", "P3"}} {
		ctrls := controlsWith(
			corazaCopy("govulncheck", "govulncheck-json", ghsa, "repo-waf", tc.govulncheck, govulndbLookup(ghsa, cve)),
			corazaCopy("Trivy", "sarif", cve, "repo-waf", tc.trivy, nil),
		)
		if groups, _ := applyCorrelation(ctrls); groups != 1 {
			t.Fatalf("govulncheck %s, Trivy %s: groups = %d, want one", tc.govulncheck, tc.trivy, groups)
		}
		var counted []string
		for _, r := range ctrls["sca"].Report.Results {
			if !r.Correlated() {
				counted = append(counted, r.Priority)
			}
		}
		if len(counted) != 1 || counted[0] != "P1" {
			t.Errorf("govulncheck %s, Trivy %s: counted at %v, want P1", tc.govulncheck, tc.trivy, counted)
		}
	}
}
