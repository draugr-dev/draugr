package diff

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// imageAdvisory is one advisory about pkg at version in an image, worded as the feed words it.
func imageAdvisory(component, pkg, version, message, priority string) sarif.Result {
	return sarif.Result{
		Tool: "trivy", RuleID: "CVE-2026-121758", Level: sarif.LevelError, Message: pkg + " " + version + ", no fix available: " + message,
		Location: sarif.Location{URI: "python:3.8-slim"}, Component: component, Priority: priority,
		Package: &sarif.Package{Name: pkg, Version: version},
	}
}

// The feed rewording an advisory leaves the same package at the same version in the same image, and
// a diff that reports it fixed and new fails a gate on a change that touched nothing.
func TestARewordedAdvisoryOnTheSamePackageIsUnchanged(t *testing.T) {
	base := report(
		imageAdvisory("api", "libc6", "2.36-9+deb12u8", "Converting crafted ISO-2022-CN-EXT input to UTF-8 character encoding", "P1"),
		imageAdvisory("api", "libc-bin", "2.36-9+deb12u8", "Converting crafted ISO-2022-CN-EXT input to UTF-8 character encoding", "P1"),
	)
	head := report(
		imageAdvisory("api", "libc6", "2.36-9+deb12u8", "Converting crafted ISO-2022-CN-EXT input in the GNU C Library", "P1"),
		imageAdvisory("api", "libc-bin", "2.36-9+deb12u8", "Converting crafted ISO-2022-CN-EXT input in the GNU C Library", "P1"),
	)
	d := Compare(base, head)
	if got := tally(d); got != [3]int{0, 2, 0} {
		t.Fatalf("new, unchanged, fixed = %v, want both unchanged", got)
	}
	if d.Unchanged[0].Message != head.Results[0].Message && d.Unchanged[0].Message != head.Results[1].Message {
		t.Errorf("unchanged carries %q, want the head's wording", d.Unchanged[0].Message)
	}
}

// Reworded and ranked differently, the advisory is the same finding in another band.
func TestARewordedAdvisoryInAnotherBandIsReranked(t *testing.T) {
	d := Compare(
		report(imageAdvisory("api", "libexpat1", "2.5.0-1+deb12u1", "libexpat through 2.10.0 contains an out-of-bounds read (not scored yet)", "P1")),
		report(imageAdvisory("api", "libexpat1", "2.5.0-1+deb12u1", "libexpat through 2.10.0 contains an out-of-bounds read", "P2")),
	)
	if len(d.Reranked) != 1 || d.Reranked[0].From != "P1" || len(d.New)+len(d.Fixed) != 0 {
		t.Errorf("reranked %d, new %d, fixed %d; want one reranked from P1", len(d.Reranked), len(d.New), len(d.Fixed))
	}
}

// Upgrading the package is a fix, whatever the wording: the version is part of the key.
func TestAnUpgradedPackageIsFixed(t *testing.T) {
	d := Compare(
		report(imageAdvisory("api", "libpam0g", "1.5.2-6+deb12u1", "pam: allowing unprivileged user to block another user namespace", "P2")),
		report(imageAdvisory("api", "libpam0g", "1.5.2-6+deb12u2", "pam: allowing unprivileged user to block another user namespace", "P2")),
	)
	if got := tally(d); got != [3]int{1, 0, 1} {
		t.Errorf("new, unchanged, fixed = %v, want the old version fixed and the new one new", got)
	}
}

// Two components holding one image are two findings, and the package pairs each with its own.
func TestThePackagePairsWithinItsComponent(t *testing.T) {
	d := Compare(
		report(
			imageAdvisory("api", "libc6", "2.36-9+deb12u8", "old wording", "P1"),
			imageAdvisory("worker", "libc6", "2.36-9+deb12u8", "old wording", "P3"),
		),
		report(
			imageAdvisory("worker", "libc6", "2.36-9+deb12u8", "new wording", "P3"),
			imageAdvisory("api", "libc6", "2.36-9+deb12u8", "new wording", "P1"),
		),
	)
	if got := tally(d); got != [3]int{0, 2, 0} || len(d.Moved)+len(d.Reranked) != 0 {
		t.Errorf("new, unchanged, fixed = %v, moved %d, reranked %d; want each unchanged in its component", got, len(d.Moved), len(d.Reranked))
	}
}

// A finding that names no package has no package key, so it pairs as it did, by its message.
func TestAFindingWithNoPackageHasNoPackageKey(t *testing.T) {
	if k := packageKey(sarif.Result{Tool: "semgrep", RuleID: "sqli"}); k != "" {
		t.Errorf("packageKey = %q, want empty", k)
	}
	if k := packageKey(sarif.Result{Tool: "trivy", Package: &sarif.Package{}}); k != "" {
		t.Errorf("packageKey of an unnamed package = %q, want empty", k)
	}
}
