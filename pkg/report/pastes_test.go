package report

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var stampPastes = flag.Bool("stamp-pastes", false, "record the console goldens the pasted runs were refreshed for")

// pastesStamp holds the digest of the console goldens the pasted runs were last refreshed for.
const pastesStamp = "testdata/pastes-refreshed-for.sha256"

// goldensDigest covers every console golden by name and content. filepath.Glob returns them sorted,
// so the digest does not depend on the directory's order.
func goldensDigest(t *testing.T) string {
	t.Helper()
	paths, err := filepath.Glob("testdata/console-*.golden")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no console goldens found: %v", err)
	}
	sum := sha256.New()
	for _, path := range paths {
		data, err := os.ReadFile(path) // #nosec G304 -- a fixed pattern under testdata/
		if err != nil {
			t.Fatal(err)
		}
		_, _ = sum.Write([]byte(filepath.Base(path) + "\x00"))
		_, _ = sum.Write(data)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// The golden test pins the layout, and go test -update accepts a new one in a second. What quotes the
// layout is prose in other files, and it stays valid markdown that reads correctly while describing
// output the renderer stopped producing. So a changed golden fails here until somebody says the pastes
// were refreshed, and -update does not say it for them.
func TestThePastedRunsFollowTheGoldens(t *testing.T) {
	digest := goldensDigest(t)
	if *stampPastes {
		if err := os.WriteFile(pastesStamp, []byte(digest+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	recorded, err := os.ReadFile(pastesStamp)
	if err != nil {
		t.Fatalf("read %s: %v\nrecord it with: make pastes-refreshed", pastesStamp, err)
	}
	if strings.TrimSpace(string(recorded)) != digest {
		t.Errorf("the console goldens changed after the pasted runs were last refreshed.\n\n"+
			"Refresh the pastes, then record that you did:\n%s", goldenPastesSteps())
	}
}

// The README's picture shows what somebody gets from installing Draugr, so it follows releases rather
// than main. A release pull request is what promotes CHANGELOG.md, so this holds that pull request
// until the picture is redrawn and passes everywhere else.
func TestTheReadmePictureShowsTheNewestRelease(t *testing.T) {
	changelog, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	newest := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindSubmatch(changelog)
	if newest == nil {
		t.Fatal("CHANGELOG.md names no release")
	}
	svg, err := os.ReadFile("../../docs/assets/scan.svg")
	if err != nil {
		t.Fatal(err)
	}
	drawn := regexp.MustCompile(`<svg [^>]*data-release="([^"]+)"`).FindSubmatch(svg)
	if drawn == nil {
		t.Fatal("docs/assets/scan.svg does not say which release it shows: run make build && RELEASE=X.Y.Z make screenshot")
	}
	if string(drawn[1]) != string(newest[1]) {
		t.Errorf("docs/assets/scan.svg shows %s, and the newest release in CHANGELOG.md is %s.\n"+
			"On the release branch: make build && RELEASE=%s make screenshot, open docs/assets/scan.svg to check it "+
			"shows the run, then commit it.",
			drawn[1], newest[1], newest[1])
	}
}
