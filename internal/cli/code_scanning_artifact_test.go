package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// imageHostAndFile is a run with a finding on an image, one on a host and one on a file.
func imageHostAndFile() report.Data {
	const image = "python:3.8-slim"
	return report.Data{Project: "shop", Version: "1.2.3", Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Control: "images", Report: sarif.Report{Results: []sarif.Result{{
			RuleID: "CVE-2023-0464", Level: sarif.LevelError, Message: "openssl", Tool: "trivy", Priority: "P2",
			Location: sarif.Location{URI: image}, Image: image,
		}}}},
		"tls": {Control: "tls", Report: sarif.Report{Results: []sarif.Result{{
			RuleID: "TLS1", Level: sarif.LevelWarning, Message: "TLS 1.0", Tool: "testssl", Priority: "P3",
			Location: sarif.Location{URI: "https://shop.example.com/"},
		}}}},
		"sast": {Control: "sast", Report: sarif.Report{Results: []sarif.Result{{
			RuleID: "G304", Level: sarif.LevelWarning, Message: "file inclusion", Tool: "gosec", Priority: "P1",
			Location: sarif.Location{URI: "cmd/shop/main.go", StartLine: 12},
		}}}},
	}}}
}

// -o writes code-scanning.sarif beside results.sarif when asked: the same findings, every location in a
// form code scanning accepts, and results.sarif unchanged, image reference and all.
func TestTheCodeScanningReportIsWhatCodeScanningAccepts(t *testing.T) {
	data := imageHostAndFile()
	dir := t.TempDir()
	if err := writeArtifacts(dir, []string{"sarif", report.CodeScanningFormat}, data, saga.Release{}, data.Run, norn.Result{}, "", ""); err != nil {
		t.Fatal(err)
	}
	upload, err := os.ReadFile(filepath.Join(dir, "code-scanning.sarif")) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	refused, err := sarif.CodeScanningRefuses(upload)
	if err != nil {
		t.Fatal(err)
	}
	if len(refused) > 0 {
		t.Errorf("code-scanning.sarif carries locations code scanning refuses: %q", refused)
	}
	back, err := sarif.FromSARIF(upload)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != 3 {
		t.Errorf("code-scanning.sarif holds %d findings, want 3", len(back.Results))
	}
	// The run's own account travels too: the category is what keeps one product's upload from
	// replacing another's.
	if !bytes.Contains(upload, []byte(`"automationDetails":{"id":"shop/"}`)) {
		t.Errorf("code-scanning.sarif lost the run's category:\n%s", upload)
	}

	record, err := os.ReadFile(filepath.Join(dir, "results.sarif")) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	if kept, _ := sarif.CodeScanningRefuses(record); !slices.Contains(kept, "python:3.8-slim") {
		t.Errorf("results.sarif no longer holds the image reference as the finding's location: %q", kept)
	}
}

// The new findings `draugr diff --format sarif` writes from two scans' results.sarif are filed under
// the head scan's category, the one its own upload on the branch carries, so code scanning compares a
// pull request with that analysis. Two products in one repository keep two categories.
func TestDiffSARIFCarriesTheScansCategory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DRAUGR_CONFIG", "")
	t.Chdir(gitRepo(t))
	seen := map[string]string{}
	for _, project := range []string{"acme-azure", "acme-gcp"} {
		head := imageHostAndFile()
		head.Project = project
		base := report.Data{Project: project, Version: head.Version}
		paths := map[string]string{}
		for name, data := range map[string]report.Data{"base": base, "head": head} {
			dir := t.TempDir()
			if err := writeArtifacts(dir, []string{"sarif"}, data, saga.Release{}, data.Run, norn.Result{}, "", ""); err != nil {
				t.Fatal(err)
			}
			paths[name] = filepath.Join(dir, "results.sarif")
		}
		var out, errOut bytes.Buffer
		cmd := newDiffCommand()
		cmd.SetArgs([]string{paths["base"], paths["head"], "--format", "sarif"})
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%s: %v\n%s", project, err, errOut.String())
		}
		var doc struct {
			Runs []struct {
				Results           []json.RawMessage `json:"results"`
				AutomationDetails *struct {
					ID string `json:"id"`
				} `json:"automationDetails"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("%s: %v\n%s", project, err, out.String())
		}
		want := report.AutomationID(project, engine.Scope{})
		if len(doc.Runs) != 1 || doc.Runs[0].AutomationDetails == nil || doc.Runs[0].AutomationDetails.ID != want {
			t.Fatalf("%s: the diff's SARIF is not filed under %q:\n%s", project, want, out.String())
		}
		if len(doc.Runs[0].Results) != 3 {
			t.Errorf("%s: %d new findings, want 3", project, len(doc.Runs[0].Results))
		}
		seen[doc.Runs[0].AutomationDetails.ID] = project
	}
	if len(seen) != 2 {
		t.Errorf("two products share a category: %v", seen)
	}
}

// A band asked for narrows code-scanning.sarif as it narrows results.sarif, and says so inside it.
func TestTheCodeScanningReportIsNarrowedLikeTheSARIF(t *testing.T) {
	data := imageHostAndFile()
	dir := t.TempDir()
	if err := writeArtifacts(dir, []string{report.CodeScanningFormat}, data, saga.Release{}, data.Run, norn.Result{}, "", "P1"); err != nil {
		t.Fatal(err)
	}
	upload, err := os.ReadFile(filepath.Join(dir, "code-scanning.sarif")) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	back, err := sarif.FromSARIF(upload)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != 1 || back.Results[0].RuleID != "G304" {
		t.Errorf("narrowed to P1 holds %+v, want G304 alone", back.Results)
	}
	if !strings.Contains(string(upload), "draugr/min-priority") {
		t.Errorf("the narrowed file does not say it was narrowed:\n%s", upload)
	}
}
