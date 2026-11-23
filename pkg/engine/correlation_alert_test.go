package engine

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// lodashAlert is a Dependabot alert, imported from GitHub, of a lodash advisory in repo's manifest:
// its GitHub advisory id as the rule, the aliases GitHub lists, and the versions it affects, with no
// installed version.
func lodashAlert(repo, manifest, ghsa, affected string, aliases ...string) sarif.Result {
	return sarif.Result{
		Tool: "Dependabot", Scanner: sarif.ImportScanner, ImportFormat: "github-dependabot",
		RuleID: ghsa, Aliases: aliases, Level: sarif.LevelError, Score: 7.2, HasScore: true,
		Component: "shop", ImportedRepository: repo,
		Location: sarif.Location{URI: manifest},
		Package:  &sarif.Package{Name: "lodash", Ecosystem: "npm", FixedVersion: "4.17.21", Affected: affected},
	}
}

// lodashNative is Trivy's finding of a lodash advisory at the version repo's manifest installs.
func lodashNative(repo, manifest, rule, version string) sarif.Result {
	return sarif.Result{
		Tool: "trivy", RuleID: rule, Level: sarif.LevelError, Score: 7.2, HasScore: true,
		Component: "shop", Repository: repo,
		Location: sarif.Location{URI: manifest, StartLine: 1},
		Package: &sarif.Package{Name: "lodash", Version: version, FixedVersion: "4.17.21",
			Ecosystem: "npm", PURL: "pkg:npm/lodash@" + version},
	}
}

const (
	lodashGHSA = "GHSA-35jh-r3h4-6jhm"
	lodashCVE  = "CVE-2021-23337"
)

// countedBy is each counted finding, by repository, as "tool rule".
func countedBy(results []sarif.Result) map[string][]string {
	out := map[string][]string{}
	for _, r := range results {
		if !r.Correlated() {
			out[placedRepository(r)] = append(out[placedRepository(r)], r.Tool+" "+r.RuleID)
		}
	}
	return out
}

// A Dependabot alert and Trivy's finding of the same advisory in the same package and manifest, at
// an installed version inside the alert's range, are one flaw: counted once, under the copy that
// names the version installed, with the alert named behind it. Over two repositories each counts
// its own.
func TestADependabotAlertIsCountedOnceWithTheNativeCopy(t *testing.T) {
	ctrls := controlsWith(
		lodashAlert("repo-web", "web/package-lock.json", lodashGHSA, "< 4.17.21", lodashCVE),
		lodashNative("repo-web", "web/package-lock.json", lodashCVE, "4.17.20"),
		lodashAlert("repo-api", "package-lock.json", lodashGHSA, "< 4.17.21", lodashCVE),
		lodashNative("repo-api", "package-lock.json", lodashCVE, "4.17.15"),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Fatalf("groups = %d, want one flaw per repository", groups)
	}
	results := ctrls["sca"].Report.Results
	want := map[string][]string{"repo-web": {"trivy " + lodashCVE}, "repo-api": {"trivy " + lodashCVE}}
	if got := countedBy(results); !reflect.DeepEqual(got, want) {
		t.Errorf("counted = %v, want %v", got, want)
	}
	for _, r := range results {
		if r.Tool == "trivy" {
			if also := r.Correlation.AlsoFoundBy; len(also) != 1 || also[0].Tool != "imported Dependabot (github-dependabot)" ||
				also[0].RuleID != lodashGHSA {
				t.Errorf("%s: alsoFoundBy = %+v, want the Dependabot alert", placedRepository(r), also)
			}
		} else if r.Correlation == nil || r.Correlation.CountedUnder != "trivy" {
			t.Errorf("%s alert: correlation = %+v, want counted under trivy", placedRepository(r), r.Correlation)
		}
	}
	if got := ctrls["sca"].Summary.Errors; got != 2 {
		t.Errorf("errors = %d, want 2 counted", got)
	}
}

// An alert with no CVE meets a copy Trivy reports under the GitHub advisory id itself.
func TestADependabotAlertWithNoCVEJoinsOnItsAdvisoryID(t *testing.T) {
	ctrls := controlsWith(
		lodashAlert("repo-web", "package-lock.json", lodashGHSA, ">= 4.0.0, < 4.17.21"),
		lodashNative("repo-web", "package-lock.json", lodashGHSA, "4.17.20"),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	if got := countedBy(ctrls["sca"].Report.Results); !reflect.DeepEqual(got, map[string][]string{"repo-web": {"trivy " + lodashGHSA}}) {
		t.Errorf("counted = %v, want Trivy's copy", got)
	}
}

// Wherever the alert cannot be shown to be the native copy's flaw, both stay counted: an installed
// version outside the range, another manifest, another repository, another advisory, a range or a
// version that does not parse, and two installed versions inside the range in one file.
func TestADependabotAlertStaysCountedWhereNothingShowsItIsTheSameFlaw(t *testing.T) {
	for name, results := range map[string][]sarif.Result{
		"version outside the range": {
			lodashAlert("repo-web", "package-lock.json", lodashGHSA, "< 4.17.21", lodashCVE),
			lodashNative("repo-web", "package-lock.json", lodashCVE, "4.17.21"),
		},
		"another manifest": {
			lodashAlert("repo-web", "package-lock.json", lodashGHSA, "< 4.17.21", lodashCVE),
			lodashNative("repo-web", "web/package-lock.json", lodashCVE, "4.17.20"),
		},
		"another repository": {
			lodashAlert("repo-web", "package-lock.json", lodashGHSA, "< 4.17.21", lodashCVE),
			lodashNative("repo-api", "package-lock.json", lodashCVE, "4.17.20"),
		},
		"another advisory": {
			lodashAlert("repo-web", "package-lock.json", lodashGHSA, "< 4.17.21", lodashCVE),
			lodashNative("repo-web", "package-lock.json", "CVE-2020-8203", "4.17.20"),
		},
		"a range that does not parse": {
			lodashAlert("repo-web", "package-lock.json", lodashGHSA, "~> 4.17", lodashCVE),
			lodashNative("repo-web", "package-lock.json", lodashCVE, "4.17.20"),
		},
		"two installed versions": {
			lodashAlert("repo-web", "package-lock.json", lodashGHSA, "< 4.17.21", lodashCVE),
			lodashNative("repo-web", "package-lock.json", lodashCVE, "4.17.20"),
			lodashNative("repo-web", "package-lock.json", lodashCVE, "4.17.15"),
		},
	} {
		ctrls := controlsWith(results...)
		applyCorrelation(ctrls)
		for _, r := range ctrls["sca"].Report.Results {
			if r.Correlated() {
				t.Errorf("%s: %s %s counted under %s, want every copy counted", name, r.Tool, r.RuleID, r.Correlation.CountedUnder)
			}
		}
	}
}

// The merged finding keeps the higher rating: an alert in a higher band than the native copy is the
// one counted, and in the same band the copy naming the installed version is, whichever comes first.
func TestADependabotAlertInAHigherBandKeepsTheCount(t *testing.T) {
	for name, tc := range map[string]struct {
		alertBand, nativeBand, want string
	}{
		"alert higher": {"P1", "P2", "Dependabot " + lodashGHSA},
		"same band":    {"P2", "P2", "trivy " + lodashCVE},
	} {
		alert := lodashAlert("repo-web", "package-lock.json", lodashGHSA, "< 4.17.21", lodashCVE)
		native := lodashNative("repo-web", "package-lock.json", lodashCVE, "4.17.20")
		alert.Priority, native.Priority = tc.alertBand, tc.nativeBand
		alert.Score = 9.1
		ctrls := controlsWith(alert, native)
		if groups, _ := applyCorrelation(ctrls); groups != 1 {
			t.Fatalf("%s: groups = %d, want 1", name, groups)
		}
		if got := countedBy(ctrls["sca"].Report.Results); !reflect.DeepEqual(got, map[string][]string{"repo-web": {tc.want}}) {
			t.Errorf("%s: counted = %v, want %s", name, got, tc.want)
		}
	}
}

// A range is read as GitHub's advisories write it, bound by bound, in the package's own ecosystem's
// order, and is unknown wherever a part does not parse.
func TestInAffectedReadsGitHubRanges(t *testing.T) {
	maven := func(v string) *sarif.Package {
		return &sarif.Package{Name: "org.apache.logging.log4j:log4j-core", Version: v, Ecosystem: "maven"}
	}
	gomod := func(v string) *sarif.Package {
		return &sarif.Package{Name: "golang.org/x/net", Version: v, PURL: "pkg:golang/golang.org/x/net@" + v}
	}
	for _, tc := range []struct {
		pkg          *sarif.Package
		affected     string
		wantIn, isOK bool
	}{
		{maven("2.14.1"), ">= 2.0-beta9, < 2.15.0", true, true},
		{maven("2.0-beta9"), ">= 2.0-beta9, < 2.15.0", true, true},
		{maven("2.15.0"), ">= 2.0-beta9, < 2.15.0", false, true},
		{maven("1.2.17"), ">= 2.0-beta9, < 2.15.0", false, true},
		{maven("2.17.0"), "= 2.17.0", true, true},
		{maven("2.17.1"), "<= 2.17.0", false, true},
		{maven("2.17.1"), "> 2.17.0", true, true},
		{gomod("v0.16.0"), "< 0.17.0", true, true},
		{gomod("v0.17.0"), "< 0.17.0", false, true},
		{maven("2.14.1"), "~> 2.14", false, false},
		{maven("2.14.1"), "< 2.15.0,", false, false},
		{maven("2.14.1"), "< later", false, false},
		{maven("unknown"), "< 2.15.0", false, false},
		{&sarif.Package{Name: "x", Version: "1.0", Ecosystem: "nothing-known"}, "< 2.0", false, false},
	} {
		in, ok := inAffected(tc.pkg, tc.affected)
		if in != tc.wantIn || ok != tc.isOK {
			t.Errorf("%s in %q = %v, %v; want %v, %v", tc.pkg.Version, tc.affected, in, ok, tc.wantIn, tc.isOK)
		}
	}
}
