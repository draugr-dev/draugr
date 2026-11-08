package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Trivy and Grype write one operating system package in different notations. Each pair here is the
// same package as the two scanners wrote it (the Debian pair from a Trivy 0.76.1 and Grype 0.121.0
// scan of debian:12-slim), and keys as one; each package in the second list differs in fact, and
// keeps its own key.
func TestAnOperatingSystemPackageKeysAlikeInEitherScannersNotation(t *testing.T) {
	same := []struct{ name, trivy, grype string }{
		{"epoch and upstream",
			"pkg:deb/debian/login@4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&epoch=1",
			"pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&upstream=shadow"},
		{"upstream alone",
			"pkg:deb/debian/libc6@2.36-9%2Bdeb12u13?arch=amd64&distro=debian-12.15",
			"pkg:deb/debian/libc6@2.36-9%2Bdeb12u13?arch=amd64&distro=debian-12.15&upstream=glibc"},
		{"alpine distro",
			"pkg:apk/alpine/busybox@1.37.0-r20?arch=x86_64&distro=3.24.2",
			"pkg:apk/alpine/busybox@1.37.0-r20?arch=x86_64&distro=alpine-3.24.2"},
		{"rpm epoch",
			"pkg:rpm/redhat/openssl@3.0.7-27.el9?arch=x86_64&epoch=1",
			"pkg:rpm/redhat/openssl@1:3.0.7-27.el9?arch=x86_64"},
	}
	for _, c := range same {
		if a, b := correlationPURL(c.trivy), correlationPURL(c.grype); a != b {
			t.Errorf("%s: keys differ\n trivy %s\n grype %s", c.name, a, b)
		}
	}

	different := [][2]string{
		{"pkg:deb/debian/login@4.13?arch=amd64&epoch=1", "pkg:deb/debian/login@4.13?arch=amd64&epoch=2"},
		{"pkg:deb/debian/login@4.13?arch=amd64", "pkg:deb/debian/login@4.13?arch=arm64"},
		{"pkg:deb/debian/login@4.13?distro=debian-12", "pkg:deb/debian/login@4.13?distro=debian-11"},
		{"pkg:deb/debian/login@4.13", "pkg:deb/debian/login@4.14"},
	}
	for _, d := range different {
		if correlationPURL(d[0]) == correlationPURL(d[1]) {
			t.Errorf("%s and %s key alike, and are two packages", d[0], d[1])
		}
	}

	// A URL that does not parse as one is compared as written, and a language package is untouched.
	for _, purl := range []string{"pkg:deb/debian/login", "pkg:pypi/flask@0.12.2?upstream=x"} {
		if got := correlationPURL(purl); got != purl {
			t.Errorf("%s keyed as %s", purl, got)
		}
	}
}

// Through correlation, the issue's pair counts once and both findings stay in the report.
func TestTrivyAndGrypeCopiesOfAnOSPackageFlawCountOnce(t *testing.T) {
	ctrls := controlsWith(
		found("trivy", "CVE-2023-4641",
			"pkg:deb/debian/login@4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&epoch=1", sarif.LevelWarning, 5.5),
		found("grype", "CVE-2023-4641",
			"pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&upstream=shadow", sarif.LevelWarning, 5.5),
	)
	groups, _ := applyCorrelation(ctrls)
	if groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	if len(ctrls["sca"].Report.Results) != 2 {
		t.Fatalf("results = %d, want both kept", len(ctrls["sca"].Report.Results))
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 1 {
		t.Errorf("counted %d, want 1", n)
	}
}
