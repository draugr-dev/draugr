package engine

import (
	"maps"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// xText is one scanner's finding of a golang.org/x/text advisory in component's repository, read from
// its go.mod at version, written as the scanner writes it.
func xText(tool, rule, component, repo, version string, aliases ...string) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: sarif.LevelError, Component: component, Repository: repo, Aliases: aliases,
		Location: sarif.Location{URI: "go.mod", StartLine: 5},
		Package: &sarif.Package{Name: "golang.org/x/text", Version: version, FixedVersion: "0.3.3",
			Ecosystem: "gomod", PURL: "pkg:golang/golang.org/x/text@" + version},
	}
}

// Trivy names a Go module version as go.mod does, v0.3.0, and keys each golang.org/x/text flaw on its
// CVE. A scanner reading the version from an OSV record may write it without the "v", 0.3.0, and key
// the same flaw on its Go advisory id with the CVE among its aliases. The two spellings are one module
// version, so each advisory is one flaw, counted once in each of two repositories with the other
// scanner's copy behind it.
func TestCorrelationJoinsAGoModuleVersionWrittenWithAndWithoutItsV(t *testing.T) {
	pairs := map[string]string{
		"CVE-2020-14040": "GO-2020-0015",
		"CVE-2021-38561": "GO-2021-0113",
		"CVE-2022-32149": "GO-2022-1059",
		"CVE-2026-56852": "GO-2026-5970",
		"CVE-2026-56851": "GO-2026-6629",
	}
	repos := []string{"repo-api", "repo-worker"}
	var results []sarif.Result
	for _, repo := range repos {
		for _, cve := range slices.Sorted(maps.Keys(pairs)) {
			results = append(results,
				xText("trivy", cve, "api", repo, "v0.3.0"),
				xText("osv-scanner", pairs[cve], "api", repo, "0.3.0", cve))
		}
	}
	ctrls := controlsWith(results...)
	if groups, _ := applyCorrelation(ctrls); groups != len(pairs)*len(repos) {
		t.Fatalf("groups = %d, want one per advisory per repository, %d", groups, len(pairs)*len(repos))
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != len(pairs)*len(repos) {
		t.Errorf("counted %d, want %d: each advisory once in each repository", n, len(pairs)*len(repos))
	}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Correlated() {
			continue
		}
		other := "osv-scanner"
		if r.Tool == other {
			other = "trivy"
		}
		if r.Correlation == nil || len(r.Correlation.AlsoFoundBy) != 1 || r.Correlation.AlsoFoundBy[0].Tool != other {
			t.Errorf("%s %s in %s: correlation %+v, want %s's copy behind it", r.Tool, r.RuleID, r.Repository, r.Correlation, other)
		}
	}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Tool == "osv-scanner" && r.Package.Version != "0.3.0" {
			t.Errorf("the finding's version was rewritten to %q; only the key adds the v", r.Package.Version)
		}
	}
}

// A copy with no package URL meets the URL-keyed copy of the same Go module version whichever of the
// two writes the "v".
func TestCorrelationJoinsAGoCopyWithoutAPackageURLWhicheverWritesTheV(t *testing.T) {
	withURL := xText("trivy", "CVE-2022-32149", "api", "repo-api", "v0.3.0")
	without := xText("osv-scanner", "CVE-2022-32149", "api", "repo-api", "0.3.0")
	without.Package.PURL = ""
	ctrls := controlsWith(withURL, without)
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Errorf("groups = %d, want the two copies as one flaw", groups)
	}
}

// Only a version that starts with a digit gains a "v". A pseudo-version and a +incompatible version
// are compared with the rest as written, and every other ecosystem's URL is compared as written.
func TestCorrelationPURLAddsOnlyAGoModulesMissingV(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:golang/golang.org/x/text@0.3.0":                                 "pkg:golang/golang.org/x/text@v0.3.0",
		"pkg:golang/golang.org/x/text@v0.3.0":                                "pkg:golang/golang.org/x/text@v0.3.0",
		"pkg:golang/github.com/Azure/go-ntlmssp@0.0.0-20221128193559-754e69": "pkg:golang/github.com/azure/go-ntlmssp@v0.0.0-20221128193559-754e69",
		"pkg:golang/github.com/docker/docker@20.10.7+incompatible":           "pkg:golang/github.com/docker/docker@v20.10.7+incompatible",
		"pkg:golang/github.com/docker/docker@v20.10.7%2Bincompatible":        "pkg:golang/github.com/docker/docker@v20.10.7%2bincompatible",
		"pkg:golang/golang.org/x/text@0.3.0?type=module":                     "pkg:golang/golang.org/x/text@v0.3.0?type=module",
		"pkg:golang/golang.org/x/text":                                       "pkg:golang/golang.org/x/text",
		"pkg:npm/lodash@4.17.20":                                             "pkg:npm/lodash@4.17.20",
	} {
		if got := correlationPURL(in); got != want {
			t.Errorf("correlationPURL(%q) = %q, want %q", in, got, want)
		}
	}
}
