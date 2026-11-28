package mcp

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
)

// detectRepository is a Go module beside a descriptor that sets config.detect and names no control,
// the descriptor `draugr init` writes for it. The test runs from the directory, since a relative url
// resolves against where Draugr runs.
func detectRepository(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":           "module app\n\ngo 1.22\n",
		"main.go":          "package main\n",
		"draugr.saga.yaml": "project: app\nconfig:\n  detect: true\ncomponents:\n  - name: app\n    repositories:\n      - url: .\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	return filepath.Join(dir, "draugr.saga.yaml")
}

// check_tools asks for what a scan of a detect descriptor runs: the go.mod turns on gosec and
// govulncheck, which the descriptor never names.
func TestCheckToolsRequiresWhatDetectTurnsOn(t *testing.T) {
	path := detectRepository(t)
	t.Setenv("PATH", t.TempDir())
	_, out, err := checkToolsTool(builtins.Registry(), nil)(context.Background(), nil, CheckToolsInput{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	names := toolNamesOf(out)
	for _, want := range []string{"gitleaks", "gosec", "govulncheck", "semgrep", "trivy"} {
		if !slices.Contains(names, want) {
			t.Errorf("tools = %v, want %s among them", names, want)
		}
	}
}

// validate_saga says the descriptor detects, since its controls list is empty and would otherwise
// read as a descriptor that checks nothing.
func TestValidateSagaSaysTheDescriptorDetects(t *testing.T) {
	path := detectRepository(t)
	_, out, err := ValidateSagaTool(context.Background(), nil, ValidateInput{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Valid || !out.Detect || len(out.Controls) != 0 {
		t.Errorf("valid = %v, detect = %v, controls = %v; want valid, detect and the controls as written, none",
			out.Valid, out.Detect, out.Controls)
	}
}
