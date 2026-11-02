package report

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A scanner or an imported SARIF can write a fixed version that names no release once its
// separators and bounds are taken away. Those findings join a package's group like any other, and
// the release chosen for the group must still be the one the other findings name.
var namesNoRelease = []string{",", ">=", " , >= ", ">=,"}

func TestAFixedVersionNamingNoReleaseTakesNoPartInTheTarget(t *testing.T) {
	for _, fixed := range namesNoRelease {
		got := upgradeTarget([]finding{
			versioned("pkg:npm/lodash@4.17.15", "npm", "4.17.15", fixed),
			versioned("pkg:npm/lodash@4.17.15", "npm", "4.17.15", "4.17.21"),
		})
		if got != "4.17.21" {
			t.Errorf("fixed %q beside 4.17.21: target = %q, want 4.17.21", fixed, got)
		}
		if got := upgradeTarget([]finding{versioned("pkg:npm/lodash@4.17.15", "npm", "4.17.15", fixed)}); got != "" {
			t.Errorf("fixed %q alone: target = %q, want none", fixed, got)
		}
	}
}

func TestAPolicyIgnoresAFixedVersionNamingNoRelease(t *testing.T) {
	for _, fixed := range namesNoRelease {
		got, _ := groupActions([]finding{
			upgradeFinding("CVE-1", "P1", "web", "minor", "npm", "jquery", "1.8.3", fixed),
			upgradeFinding("CVE-2", "P2", "web", "minor", "npm", "jquery", "1.8.3", "1.12.2"),
		}, nil)
		var targets []string
		for _, a := range got {
			targets = append(targets, a.target())
		}
		found := false
		for _, target := range targets {
			found = found || target == "1.12.2"
		}
		if !found {
			t.Errorf("fixed %q beside 1.12.2 under a minor policy: targets %q, want 1.12.2 among them", fixed, targets)
		}
	}
}

func TestReleaseClearsWithNoFixIsUndecided(t *testing.T) {
	if cleared, known := releaseClears(newVersions("npm"), "1.0.0", "0.9.0", nil); cleared || known {
		t.Errorf("releaseClears with no fixes = %v, %v, want false, false", cleared, known)
	}
}

// TestActionsForSurvivesAFixedVersionNamingNoRelease drives the whole fix list over two components
// in two repositories, each with one finding whose fixed version names no release beside one that
// names 4.17.21.
func TestActionsForSurvivesAFixedVersionNamingNoRelease(t *testing.T) {
	res := func(rule, component, repo, fixed string) sarif.Result {
		return sarif.Result{
			RuleID: rule, Priority: "P1", Level: sarif.LevelError, Component: component,
			Location: sarif.Location{URI: repo + "/package-lock.json", StartLine: 12},
			Package: &sarif.Package{Name: "lodash", Version: "4.17.15", FixedVersion: fixed,
				PURL: "pkg:npm/lodash@4.17.15", Ecosystem: "npm"},
		}
	}
	got := ActionsFor(map[string]sarif.Report{"sca": {Results: []sarif.Result{
		res("CVE-1", "api", "repo-api", ","),
		res("CVE-2", "api", "repo-api", "4.17.21"),
		res("CVE-1", "worker", "repo-worker", ">="),
		res("CVE-2", "worker", "repo-worker", "4.17.21"),
	}}})
	targets := map[string]bool{}
	for _, a := range got {
		targets[a.Target] = true
	}
	if !targets["4.17.21"] {
		t.Errorf("no action targets 4.17.21: %+v", got)
	}
}
