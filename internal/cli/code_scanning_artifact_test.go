package cli

import (
	"bytes"
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
