package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/detect"
)

// detectShop is two repositories, a Go module in api and plain files in web, under a descriptor that
// sets config.detect and writes extra under it. The test runs from the directory, where the relative
// urls resolve.
func detectShop(t *testing.T, config string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "shop")
	layout(t, dir, map[string]string{
		"api/go.mod":    "module api\n\ngo 1.26\n",
		"api/main.go":   "package main\n",
		"web/README.md": "web\n",
		"draugr.saga.yaml": "project: shop\nconfig:\n  detect: true\n" + config + "components:\n" +
			"  - name: api\n    repositories:\n      - url: ./api\n" +
			"  - name: web\n    repositories:\n      - url: ./web\n",
	})
	t.Chdir(dir)
	orig := scanInstallOffer
	t.Cleanup(func() { scanInstallOffer = orig })
	scanInstallOffer.terminal = func() bool { return false }
	scanInstallOffer.lookPath = notInstalled("go")
}

// A descriptor that sets config.detect, on a machine without Go: the go.mod in one repository turns
// gosec and govulncheck on, nobody named them, so they are turned off and reported as files not
// checked under the component whose repository holds them, and the run is not incomplete. FOUND
// names each file joined to its repository, and report.json carries the same rows.
func TestADetectRunTurnsOffAScannerOnlyTheFilesAskedFor(t *testing.T) {
	detectShop(t, "")
	reg, ran := goRegistry()

	var out bytes.Buffer
	err := runScan(context.Background(), "", scanOptions{format: "console", noPublish: true}, reg, &out)
	if err != nil && err.Error() != "policy verdict: fail" {
		t.Fatalf("the run ended %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"FOUND  read from the tree · what each kind of file turned on\n",
		"api/go.mod  gosec off · govulncheck off\n",
		"not-checked · api",
		"api/go.mod  gosec needs Go\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("console missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ERROR") || strings.Contains(got, "not-checked · web") {
		t.Errorf("a scanner the files chose shows as an error, or under the wrong component:\n%s", got)
	}
	for _, off := range []string{"gosec", "govulncheck"} {
		if n := ran[off].Load(); n != 0 {
			t.Errorf("%s ran %d times after it was turned off", off, n)
		}
	}
	if ran["semgrep"].Load() != 2 || ran["trivy-fs"].Load() != 2 {
		t.Errorf("semgrep ran %d times and trivy-fs %d, want once per repository", ran["semgrep"].Load(), ran["trivy-fs"].Load())
	}

	out.Reset()
	if err := runScan(context.Background(), "", scanOptions{format: "json", noPublish: true}, reg, &out); err != nil &&
		err.Error() != "policy verdict: fail" {
		t.Fatalf("the json run ended %v", err)
	}
	var doc struct {
		Found []struct {
			Kind, Did string
			Paths     []string
		} `json:"found"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Found) != 1 || doc.Found[0].Kind != "go" || !slices.Equal(doc.Found[0].Paths, []string{"api/go.mod"}) ||
		doc.Found[0].Did != "gosec off · govulncheck off" {
		t.Errorf("report.json found = %+v", doc.Found)
	}
}

// A scanner the descriptor names under config.controls is one somebody asked for, detect or not, so
// a machine that cannot run it fails the run rather than reporting a gap.
func TestADetectRunFailsAScannerTheDescriptorNames(t *testing.T) {
	detectShop(t, "  controls:\n    sast:\n      gosec:\n        enabled: true\n")
	reg, ran := goRegistry()

	var out bytes.Buffer
	err := runScan(context.Background(), "", scanOptions{format: "console", noPublish: true}, reg, &out)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("gosec, named and unable to run, ended the run with %v", err)
	}
	if ran["gosec"].Load() == 0 {
		t.Error("gosec was turned off although the descriptor names it")
	}
	if ran["govulncheck"].Load() != 0 {
		t.Error("govulncheck, which only the files asked for, ran")
	}
}

// A repository config.detect cannot read is named before the scan, with the components naming it.
func TestWriteUnreadRepositoriesNamesEachOne(t *testing.T) {
	var out bytes.Buffer
	writeUnreadRepositories(&out, &detect.Result{Unread: []detect.Unread{
		{URL: "https://github.com/example/app.git", Components: []string{"api", "web"}},
	}})
	want := "warning: config.detect did not read https://github.com/example/app.git (api and web): " +
		detect.UnreadReason + ". A control only its files call for is off unless config.controls turns it on.\n"
	if out.String() != want {
		t.Errorf("got  %q\nwant %q", out.String(), want)
	}
}

// doctor on a detect descriptor prints DETECTED, a block per component with its repository and the
// files that turned controls on. gosec and govulncheck, which only the go.mod asked for, missing is
// not a failure; semgrep, which sast always runs, missing is.
func TestDoctorNamesWhatDetectTurnedOn(t *testing.T) {
	detectShop(t, "")
	base := []string{"git", "gitleaks", "semgrep", "trivy"}

	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(), "draugr.saga.yaml", doctorRun{},
		fakeDetect(base...), nil); err != nil {
		t.Fatalf("gosec and govulncheck missing failed doctor: %v\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{
		"DETECTED  config.detect turned these on, from the files that call for them\n",
		"  api\n",
		"repository  ./api",
		"go          go.mod  gosec · govulncheck",
		"gosec · govulncheck",
		"  web\n",
		"repository  ./web",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor missing %q:\n%s", want, got)
		}
	}

	out.Reset()
	if err := runDoctor(context.Background(), &out, builtins.Registry(), "draugr.saga.yaml", doctorRun{},
		fakeDetect("git", "gitleaks", "trivy"), nil); err == nil {
		t.Errorf("semgrep missing passed doctor:\n%s", out.String())
	}
}
