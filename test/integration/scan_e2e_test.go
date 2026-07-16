//go:build integration

// Package integration holds Draugr's integration tests: they exercise real external
// dependencies (a real Trivy binary, a real kind cluster) that unit tests stub out. They are
// gated behind the `integration` build tag so `go test ./...` stays fast and hermetic, and
// run in the dedicated .github/workflows/integration.yml pipeline (not on every PR).
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// draugrBin returns the Draugr binary to exercise: $DRAUGR_BIN if set, else "draugr" on PATH.
func draugrBin(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("DRAUGR_BIN"); bin != "" {
		return bin
	}
	bin, err := exec.LookPath("draugr")
	if err != nil {
		t.Fatalf("draugr not found: set $DRAUGR_BIN to the built binary or put draugr on PATH: %v", err)
	}
	return bin
}

// TestScanImageWithRealTrivy runs the built `draugr scan` end-to-end against a fixture Saga
// that scans a pinned, deliberately-old image with a real Trivy. It proves the whole path —
// CLI → engine → the tool adapter exec'ing Trivy → SARIF normalization → artifact writing —
// which unit tests only cover with a stubbed tool runner.
func TestScanImageWithRealTrivy(t *testing.T) {
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not on PATH; integration test requires a real Trivy")
	}

	out := t.TempDir()
	cmd := exec.Command(draugrBin(t),
		"scan", "testdata/image-scan.saga.yaml",
		"--output", out,
		"--log-level", "warn",
	)
	combined, err := cmd.CombinedOutput()
	// A non-zero exit is expected: an old image trips the default (error) gate. The scan still
	// writes its artifacts before the gate exits, so we assert on those, not the exit code.
	t.Logf("draugr scan exit=%v\n%s", err, combined)

	sarifPath := filepath.Join(out, "results.sarif")
	if _, err := os.Stat(sarifPath); err != nil {
		t.Fatalf("expected %s to be written: %v", sarifPath, err)
	}
	if _, err := os.Stat(filepath.Join(out, "report.json")); err != nil {
		t.Fatalf("expected report.json to be written: %v", err)
	}

	data, err := os.ReadFile(sarifPath) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	report, err := sarif.FromSARIF(data)
	if err != nil {
		t.Fatalf("results.sarif is not valid SARIF: %v", err)
	}
	if report.Tool != "Draugr" {
		t.Errorf("SARIF tool = %q, want the single Draugr driver", report.Tool)
	}
	// The whole point of the integration test: real Trivy actually found vulnerabilities in
	// the image, and they flowed through normalization into the merged report.
	if len(report.Results) == 0 {
		t.Errorf("expected real Trivy findings for the fixture image, got 0 results")
	}
}
