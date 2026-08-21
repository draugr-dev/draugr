package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// found is a finding as one scanner reports it.
func found(tool, rule, purl string, level sarif.Level, score float64) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: level, Score: score, HasScore: true,
		Repository: "repo-a", Component: "api",
		Package: &sarif.Package{Name: "flask", PURL: purl},
	}
}

func TestCorrelationCountsOneFlawOnce(t *testing.T) {
	// The arithmetic this exists to fix: two scanners, one flaw, one count. Both findings stay
	// in the report — the disagreement between two scanners is the reason to run two.
	ctrls := controlsWith(
		found("trivy", "CVE-2019-1010083", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
		found("grype", "CVE-2019-1010083-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
	)
	groups, _ := applyCorrelation(ctrls)
	if groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	if len(ctrls["sca"].Report.Results) != 2 {
		t.Fatalf("results = %d, want both kept", len(ctrls["sca"].Report.Results))
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 1 {
		t.Errorf("counted %d, want 1 — the flaw is one thing to fix", n)
	}
}

func TestCorrelationCountsTheStrongerReading(t *testing.T) {
	// The scanners disagree: medium against low for the same CVE. Reporting the lower would be
	// the report arguing itself down.
	ctrls := controlsWith(
		found("trivy", "CVE-2026-27205", "pkg:pypi/flask@0.12.2", sarif.LevelWarning, 4.3),
		found("grype", "CVE-2026-27205-flask", "pkg:pypi/flask@0.12.2", sarif.LevelNote, 2.3),
	)
	applyCorrelation(ctrls)
	for _, r := range ctrls["sca"].Report.Results {
		if r.Correlated() {
			continue
		}
		if r.Tool != "trivy" || r.Score != 4.3 {
			t.Errorf("counted %s at %v, want the stronger reading", r.Tool, r.Score)
		}
		if len(r.Correlation.AlsoFoundBy) != 1 || r.Correlation.AlsoFoundBy[0] != "grype" {
			t.Errorf("alsoFoundBy = %v, want grype named", r.Correlation.AlsoFoundBy)
		}
	}
}

func TestCorrelationBreaksTiesTowardTheCanonicalIdentifier(t *testing.T) {
	// Equal severity. The undecorated id is what a reader can look up and what an exclusion is
	// most likely already written against.
	ctrls := controlsWith(
		found("grype", "CVE-2018-1000656-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
		found("trivy", "CVE-2018-1000656", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
	)
	applyCorrelation(ctrls)
	for _, r := range ctrls["sca"].Report.Results {
		if !r.Correlated() && r.RuleID != "CVE-2018-1000656" {
			t.Errorf("counted %q, want the canonical identifier", r.RuleID)
		}
	}
}

func TestCorrelationDoesNotCollapseDifferentRepositories(t *testing.T) {
	// A component can hold several, and the same dependency in two of them is two things to fix.
	a := found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	b := found("grype", "CVE-2024-11111-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	b.Repository = "repo-b"
	ctrls := controlsWith(a, b)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none across repositories", groups)
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 2 {
		t.Errorf("counted %d, want both", n)
	}
}

func TestCorrelationDoesNotCollapseDifferentPackages(t *testing.T) {
	// One advisory can affect several packages, which is exactly why Grype decorates its ids.
	ctrls := controlsWith(
		found("grype", "CVE-2024-11111-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
		found("grype", "CVE-2024-11111-django", "pkg:pypi/django@2.0", sarif.LevelError, 8.7),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none across packages", groups)
	}
}

func TestCorrelationLeavesFindingsThatAreNotVulnerabilities(t *testing.T) {
	// A leaked credential and a misconfigured resource have no advisory and no package. Inventing
	// a key for them would collapse findings that are not the same flaw.
	ctrls := controlsWith(
		sarif.Result{Tool: "gitleaks", RuleID: "private-key", Level: sarif.LevelError, Repository: "r"},
		sarif.Result{Tool: "semgrep", RuleID: "private-key", Level: sarif.LevelError, Repository: "r"},
	)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none without a package and an advisory", groups)
	}
}

func TestCorrelationCarriesADecisionAcrossEveryCopy(t *testing.T) {
	// A reader who excluded a vulnerability excused the vulnerability, not one tool's report of
	// it. Leaving the other copy counted is an exclusion that silently stops working the day a
	// second scanner is added.
	a := found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	a.Suppression = &sarif.Suppression{Kind: "external", Justification: "accepted for now"}
	b := found("grype", "CVE-2024-11111-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	ctrls := controlsWith(a, b)

	_, extra := applyCorrelation(ctrls)
	if extra != 1 {
		t.Errorf("extra suppressed = %d, want the second copy excused too", extra)
	}
	for _, r := range ctrls["sca"].Report.Results {
		if !r.Suppressed() {
			t.Errorf("%s copy still counted after the flaw was excused", r.Tool)
			continue
		}
		if r.Suppression.Justification != "accepted for now" {
			t.Errorf("justification = %q, want the reason that was given", r.Suppression.Justification)
		}
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 0 {
		t.Errorf("counted %d, want none", n)
	}
}

func TestCorrelationIsANoopForOneScanner(t *testing.T) {
	ctrls := controlsWith(found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7))
	groups, extra := applyCorrelation(ctrls)
	if groups != 0 || extra != 0 {
		t.Errorf("groups=%d extra=%d, want zero for a single scanner", groups, extra)
	}
	if ctrls["sca"].Report.Results[0].Correlation != nil {
		t.Error("a finding only one scanner reported should carry no correlation")
	}
}

func TestCorrelationIsNotPartOfFingerprint(t *testing.T) {
	// Which finding of a group happens to be counted is a fact about this run's scanner
	// selection, not about the finding. Folding it in would churn a diff the day somebody adds
	// a second scanner.
	base := found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	marked := base
	marked.Correlation = &sarif.Correlation{AlsoFoundBy: []string{"grype"}}
	if base.Fingerprint() != marked.Fingerprint() {
		t.Error("correlation changed the fingerprint")
	}
}
