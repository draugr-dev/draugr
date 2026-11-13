package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// upstreamImagesRun is two images somebody else builds, each with a fixed package inside, beside two
// dependencies the project upgrades itself.
func upstreamImagesRun() engine.Result {
	image := func(ref, rule, pkg string) sarif.Result {
		return sarif.Result{RuleID: rule, Tool: "trivy", Priority: "P2", Level: sarif.LevelError,
			Component: "api", Image: ref, BuiltUpstream: true, Location: sarif.Location{URI: ref},
			Message: rule + " in " + pkg,
			Package: &sarif.Package{Name: pkg, Version: "1.0", FixedVersion: "1.1", Ecosystem: "debian"}}
	}
	dep := func(rule, pkg string, line int) sarif.Result {
		return sarif.Result{RuleID: rule, Tool: "trivy", Priority: "P1", Level: sarif.LevelError,
			Component: "api", Message: rule + " in " + pkg,
			Location: sarif.Location{URI: "web/package-lock.json", StartLine: line},
			Package:  &sarif.Package{Name: pkg, Version: "1.0.0", FixedVersion: "1.0.1", Ecosystem: "npm"}}
	}
	return engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			image("python:3.8-slim", "CVE-2025-0001", "openssl"),
			image("python:3.8-slim", "CVE-2025-0002", "libc6"),
			image("redis:6", "CVE-2025-0003", "zlib1g"),
		}}},
		"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			dep("CVE-2024-0001", "left-pad", 4),
			dep("CVE-2024-0002", "nanoid", 9),
		}}},
	}}
}

func renderUpstreamImages(t *testing.T, view View, top int) string {
	t.Helper()
	t.Setenv("COLUMNS", "")
	var out bytes.Buffer
	d := Data{Verdict: norn.Result{Verdict: norn.Fail}, View: view, TopN: top, Run: upstreamImagesRun()}
	if err := (consoleReporter{}).Render(&out, d); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// TestUpstreamImagesAreTheirOwnFirstList: an image somebody else builds is a list of its own, ahead
// of the bumps, and --top does not cut it, because one image routinely clears more than every bump
// together and a "not listed" line is where a reader stops.
func TestUpstreamImagesAreTheirOwnFirstList(t *testing.T) {
	out := renderUpstreamImages(t, ViewActions, 1)
	images := strings.Index(out, "Update an image you do not build  2 actions clear 3 findings")
	bumps := strings.Index(out, "Bump a dependency  2 actions clear 2 findings")
	if images < 0 || bumps < 0 || images > bumps {
		t.Fatalf("want the image list, counting both images, before the bumps:\n%s", out)
	}
	list := out[images:bumps]
	for _, row := range []string{"Update python:3.8-slim", "Update redis:6"} {
		if !strings.Contains(list, row) {
			t.Errorf("--top 1 cut %q from the image list:\n%s", row, out)
		}
	}
	if strings.Contains(list, "not listed") {
		t.Errorf("the image list says something is not listed:\n%s", list)
	}
	if !strings.Contains(out[bumps:], "… and 1 action not listed") {
		t.Errorf("--top 1 still cuts the bumps:\n%s", out[bumps:])
	}
	if strings.Contains(out[bumps:], "openssl") || strings.Contains(out[bumps:], "zlib1g") {
		t.Errorf("a package inside an upstream image is a bump:\n%s", out[bumps:])
	}
}

// TestFixFirstNamesTheImageToUpdate: in every view a finding in an image somebody else builds says
// to update the image, never to upgrade the package inside it, which nobody reading can do.
func TestFixFirstNamesTheImageToUpdate(t *testing.T) {
	compact := renderUpstreamImages(t, ViewCompact, -1)
	if !strings.Contains(compact, "update python:3.8-slim") || !strings.Contains(compact, "update redis:6") {
		t.Errorf("compact should name the image to update:\n%s", compact)
	}
	for _, pkg := range []string{"openssl", "libc6", "zlib1g"} {
		if strings.Contains(compact, pkg+" → ") {
			t.Errorf("compact offers an upgrade of %s inside an upstream image:\n%s", pkg, compact)
		}
	}
	if !strings.Contains(compact, "left-pad → 1.0.1") {
		t.Errorf("a dependency the project builds keeps its upgrade:\n%s", compact)
	}

	blocks := renderUpstreamImages(t, ViewFindings, -1)
	if !strings.Contains(blocks, "openssl 1.0 · fix update python:3.8-slim") {
		t.Errorf("a block should keep the package's name and give the image as the fix:\n%s", blocks)
	}
	if strings.Contains(blocks, "openssl 1.0 → ") {
		t.Errorf("a block offers an upgrade inside an upstream image:\n%s", blocks)
	}
}

// TestTheOtherFormatsNameTheImageToo: markdown and the HTML report say what the console says.
func TestTheOtherFormatsNameTheImageToo(t *testing.T) {
	f := finding{control: "images", ruleID: "CVE-1", location: "python:3.8-slim", builtUpstream: true,
		pkg: &sarif.Package{Name: "openssl", Version: "3.0.11", FixedVersion: "3.0.18"}}
	if got := markdownUpgrade(f); got != "openssl 3.0.11 · update python:3.8-slim" {
		t.Errorf("markdown cell = %q", got)
	}
	if got := fixPhrase(f); got != "update python:3.8-slim" {
		t.Errorf("fix phrase = %q", got)
	}

	// No fixed version: no newer image is known to help, so the phrase says why there is nothing.
	f.pkg.FixedVersion = ""
	if got := imageUpdate(f); got != "" {
		t.Errorf("a package with no fix names %q", got)
	}
	if got := fixPhrase(f); got != "somebody else publishes it" {
		t.Errorf("fix phrase without a fix = %q", got)
	}

	// An image the project builds keeps the package upgrade.
	own := finding{control: "images", ruleID: "CVE-1", location: "ghcr.io/acme/api:1",
		pkg: &sarif.Package{Name: "openssl", Version: "3.0.11", FixedVersion: "3.0.18"}}
	if got := markdownUpgrade(own); got != "openssl 3.0.11 → 3.0.18" {
		t.Errorf("markdown cell for an image the project builds = %q", got)
	}
	if got := compactFix(own); !strings.Contains(got, "→") {
		t.Errorf("compact cell for an image the project builds = %q", got)
	}
}
