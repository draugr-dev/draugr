package engine

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// pillow is one Pillow advisory as Trivy reports it with detectionPriority: comprehensive: from a
// requirements file whose range it read at its minimum, or from the lockfile pinning the version that
// installs.
func pillow(repo, file, version, rng, cve string) sarif.Result {
	return sarif.Result{
		Tool: "trivy", RuleID: cve, Level: sarif.LevelError, Score: 9.8, HasScore: true,
		Component: "api", Repository: repo,
		Location: sarif.Location{URI: file, StartLine: 1},
		Package: &sarif.Package{Name: "pillow", Version: version, FixedVersion: "13.0.0",
			Ecosystem: "pip", PURL: "pkg:pypi/pillow@" + version, Range: rng},
	}
}

// countedAt is each counted finding, by repository, as "rule at file".
func countedAt(results []sarif.Result) map[string][]string {
	out := map[string][]string{}
	for _, r := range results {
		if !r.Correlated() {
			out[r.Repository] = append(out[r.Repository], r.RuleID+" at "+r.Location.URI)
		}
	}
	return out
}

// A requirements.txt range read at its minimum and the uv.lock beside it pinning the package report
// one flaw, counted once at the lockfile. The range copy stays in the report as evidence counted
// under it, and the lockfile copy names it. Over two repositories each counts its own, and an
// advisory only the range reports, with nothing beside it pinning the package, stays counted.
func TestARangeMinimumIsCountedOnceAtTheLockfileBesideIt(t *testing.T) {
	const cve, only = "CVE-2026-112393", "CVE-2026-112900"
	ctrls := controlsWith(
		// The range copy first, so the lockfile is counted because it pins, not because of order.
		pillow("repo-api", "requirements.txt", "10.4", ">=10.4", cve),
		pillow("repo-api", "uv.lock", "10.4.0", "", cve),
		pillow("repo-web", "requirements.txt", "10.4", ">=10.4", cve),
		pillow("repo-web", "uv.lock", "10.4.0", "", cve),
		pillow("repo-web", "requirements.txt", "10.4", ">=10.4", only),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Fatalf("groups = %d, want one flaw per repository", groups)
	}
	want := map[string][]string{
		"repo-api": {cve + " at uv.lock"},
		"repo-web": {cve + " at uv.lock", only + " at requirements.txt"},
	}
	results := ctrls["sca"].Report.Results
	if got := countedAt(results); !reflect.DeepEqual(got, want) {
		t.Errorf("counted = %v, want %v", got, want)
	}
	for _, r := range results {
		switch {
		case r.RuleID == only:
			if r.Correlation != nil {
				t.Errorf("%s: correlation = %+v, want none", r.RuleID, r.Correlation)
			}
		case r.Location.URI == "requirements.txt":
			if !r.Correlated() || r.Correlation.CountedUnder != "trivy" {
				t.Errorf("%s range copy: correlation = %+v, want counted under trivy", r.Repository, r.Correlation)
			}
		default:
			if also := r.Correlation.AlsoFoundBy; len(also) != 1 || also[0].Location != "requirements.txt" {
				t.Errorf("%s lockfile copy: alsoFoundBy = %+v, want the requirements.txt copy", r.Repository, also)
			}
		}
	}
	if got := ctrls["sca"].Summary.Errors; got != 3 {
		t.Errorf("errors = %d, want 3 counted", got)
	}
}

// A lockfile in another directory installs for another project, and two lockfiles beside the range
// pinning the package at different versions leave no one pin to count it under. The range copy stays
// counted in both cases.
func TestARangeMinimumStaysCountedWithoutOnePinBesideIt(t *testing.T) {
	const cve = "CVE-2026-112398"
	for name, results := range map[string][]sarif.Result{
		"another directory": {
			pillow("repo-api", "app/requirements.txt", "10.4", ">=10.4", cve),
			pillow("repo-api", "uv.lock", "10.4.0", "", cve),
		},
		"two pins": {
			pillow("repo-api", "requirements.txt", "10.4", ">=10.4", cve),
			pillow("repo-api", "uv.lock", "10.4.0", "", cve),
			pillow("repo-api", "poetry.lock", "11.0.0", "", cve),
		},
	} {
		ctrls := controlsWith(results...)
		if groups, _ := applyCorrelation(ctrls); groups != 0 {
			t.Errorf("%s: groups = %d, want none", name, groups)
		}
		for _, r := range ctrls["sca"].Report.Results {
			if r.Correlated() {
				t.Errorf("%s: %s counted under %s, want every copy counted", name, r.Location.URI, r.Correlation.CountedUnder)
			}
		}
	}
}

// Preferring the pin never ranks the flaw lower: a range copy in a higher band keeps the count.
func TestARangeMinimumInAHigherBandKeepsTheCount(t *testing.T) {
	const cve = "CVE-2026-112403"
	rng, lock := pillow("repo-api", "requirements.txt", "10.4", ">=10.4", cve), pillow("repo-api", "uv.lock", "10.4.0", "", cve)
	rng.Priority, lock.Priority = "P1", "P2"
	ctrls := controlsWith(lock, rng)
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	if got := countedAt(ctrls["sca"].Report.Results); !reflect.DeepEqual(got, map[string][]string{"repo-api": {cve + " at requirements.txt"}}) {
		t.Errorf("counted = %v, want the P1 range copy", got)
	}
}
