package engine

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
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
		{"deb epoch alone",
			"pkg:deb/debian/passwd@4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&epoch=1",
			"pkg:deb/debian/passwd@1%3A4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15"},
		{"epoch zero written or left out",
			"pkg:deb/debian/tar@1.34%2Bdfsg-1.2%2Bdeb12u1?arch=amd64&distro=debian-12.15",
			"pkg:deb/debian/tar@0%3A1.34%2Bdfsg-1.2%2Bdeb12u1?arch=amd64&distro=debian-12.15"},
		{"qualifiers in another order",
			"pkg:apk/alpine/musl@1.2.5-r10?distro=3.24.2&arch=x86_64",
			"pkg:apk/alpine/musl@1.2.5-r10?arch=x86_64&distro=alpine-3.24.2&upstream=musl"},
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
		// Two binary packages built from one source package are two installs, each upgraded on its
		// own, so the source package Grype names is never what they are keyed on.
		{"pkg:deb/debian/login@1%3A4.13?arch=amd64&upstream=shadow", "pkg:deb/debian/passwd@1%3A4.13?arch=amd64&upstream=shadow"},
		{"pkg:apk/alpine/busybox@1.37.0-r20?distro=3.24.2", "pkg:apk/alpine/busybox@1.37.0-r19?distro=alpine-3.24.2"},
		{"pkg:deb/debian/libc6@2.36-9?arch=amd64", "pkg:deb/ubuntu/libc6@2.36-9?arch=amd64"},
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

// osPackageFlaw is one OS package flaw as Trivy and Grype each write it: the rule, which Grype
// suffixes with the package name, and the package URL in each scanner's notation.
type osPackageFlaw struct{ vuln, name, version, trivy, grype string }

// debianFlaws are three flaws in a Debian 12 image. login and passwd are two binary packages from
// one source package, shadow, at one version, and stay two flaws; libc6 differs between the
// scanners by upstream alone.
var debianFlaws = []osPackageFlaw{
	{"CVE-2023-4641", "login", "1:4.13+dfsg1-1+deb12u2",
		"pkg:deb/debian/login@4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&epoch=1",
		"pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&upstream=shadow"},
	{"CVE-2023-4641", "passwd", "1:4.13+dfsg1-1+deb12u2",
		"pkg:deb/debian/passwd@4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&epoch=1",
		"pkg:deb/debian/passwd@1%3A4.13%2Bdfsg1-1%2Bdeb12u2?arch=amd64&distro=debian-12.15&upstream=shadow"},
	{"CVE-2025-4802", "libc6", "2.36-9+deb12u13",
		"pkg:deb/debian/libc6@2.36-9%2Bdeb12u13?arch=amd64&distro=debian-12.15",
		"pkg:deb/debian/libc6@2.36-9%2Bdeb12u13?arch=amd64&distro=debian-12.15&upstream=glibc"},
}

// osPackageScanner reports debianFlaws in the image it scanned, in its own scanner's notation.
type osPackageScanner struct{ name string }

func (s osPackageScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s osPackageScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	var results []sarif.Result
	for _, f := range debianFlaws {
		rule, purl := f.vuln, f.trivy
		if s.name == "grype" {
			rule, purl = f.vuln+"-"+f.name, f.grype
		}
		results = append(results, sarif.Result{
			RuleID: rule, Message: f.name + " " + f.version, Level: sarif.LevelWarning, Score: 5.5, HasScore: true, Tool: s.name,
			Image: target.Identity(), Location: sarif.Location{URI: target.Identity()},
			Package: &sarif.Package{Name: f.name, Version: f.version, Ecosystem: "debian", PURL: purl},
		})
	}
	return sarif.Report{Tool: s.name, Results: results}, nil
}

// twoImageScanners plans both image scanners on each component's image.
type twoImageScanners struct{}

func (twoImageScanners) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent}
}

func (twoImageScanners) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	target := plugin.ImageTarget{Ref: "registry.example/" + comp.Name + ":1"}
	return []plugin.ScanJob{{Scanner: "trivy", Target: target}, {Scanner: "grype", Target: target}}, nil
}

func (twoImageScanners) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images", Report: sarif.Merge(reports...)}, nil
}

// Through a run with both image scanners on each of two images, every flaw counts once per image
// under one scanner and names the other, and every finding keeps the package URL its scanner wrote.
func TestARunWithBothImageScannersCountsEachOSPackageFlawOncePerImage(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(twoImageScanners{})
	reg.RegisterScanner(osPackageScanner{name: "trivy"})
	reg.RegisterScanner(osPackageScanner{name: "grype"})
	m := saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"images": {"enabled": true}}},
		Components: []saga.Component{{Name: "api"}, {Name: "worker"}},
	}
	res, err := New(reg).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	report := res.Controls["images"].Report
	perImage := len(debianFlaws)
	if len(report.Results) != 2*2*perImage {
		t.Fatalf("results = %d, want every scanner's copy kept", len(report.Results))
	}
	if n := report.Counts().Total(); n != 2*perImage {
		t.Errorf("counted %d, want %d: each flaw once in each image", n, 2*perImage)
	}
	if res.Correlated != 2*perImage {
		t.Errorf("correlated = %d, want %d", res.Correlated, 2*perImage)
	}

	written := map[string]bool{}
	for _, f := range debianFlaws {
		written[f.trivy], written[f.grype] = true, true
	}
	for _, r := range report.Results {
		if !written[r.Package.PURL] {
			t.Errorf("%s's package URL was rewritten to %s; only the key is normalized", r.Tool, r.Package.PURL)
		}
		if r.Correlated() {
			continue
		}
		if also := r.Correlation.AlsoFoundBy; len(also) != 1 || also[0].Tool == r.Tool {
			t.Errorf("%s %s in %s: also found by %+v, want the other scanner", r.Tool, r.RuleID, r.Image, also)
		}
	}
}
