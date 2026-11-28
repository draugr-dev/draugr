package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/needs"
)

// init on a Go module with a Dockerfile writes detect and no controls, and the descriptor it wrote,
// loaded and resolved as a scan loads it, turns on exactly the controls and scanners a scan of the
// same directory with no descriptor turns on.
func TestRunInitWritesDetectAndScansWhatAZeroConfigScanDoes(t *testing.T) {
	dir := t.TempDir()
	layout(t, dir, map[string]string{
		"go.mod":     "module x\ngo 1.26\nrequire golang.org/x/text v0.3.0\n",
		"main.go":    "package main\n",
		"Dockerfile": "FROM alpine\n",
	})
	t.Chdir(dir)
	var buf bytes.Buffer
	if err := runInit(".", initOptions{output: DescriptorName}, &buf); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(DescriptorName)
	if err != nil {
		t.Fatalf("expected %s written: %v", DescriptorName, err)
	}
	s := string(data)
	for _, want := range []string{"config:\n  detect: true", "url: .", "# images:"} {
		if !strings.Contains(s, want) {
			t.Errorf("generated Saga missing %q:\n%s", want, s)
		}
	}
	for _, not := range []string{"\n  controls:", "\n  reachability:"} {
		if strings.Contains(s, not) {
			t.Errorf("generated Saga writes %q, which detect decides:\n%s", not, s)
		}
	}
	if n := strings.Count(s, "\n"); n > 12 {
		t.Errorf("generated Saga is %d lines, want about 10:\n%s", n, s)
	}

	res, result, err := loadDetected(t.Context(), DescriptorName, false)
	if err != nil {
		t.Fatalf("generated Saga is not valid: %v", err)
	}
	if result == nil || len(result.Read) != 1 {
		t.Fatalf("detect read %+v, want the one repository", result)
	}
	zero, err := synthesize(".")
	if err != nil {
		t.Fatal(err)
	}
	reg := builtins.Registry()
	if got, want := usesNames(needs.Uses(reg, res.Model)), usesNames(needs.Uses(reg, zero.model)); !slices.Equal(got, want) {
		t.Errorf("the descriptor init wrote runs %v, a scan with no descriptor runs %v", got, want)
	}
	if !reflect.DeepEqual(res.Model.Config.Controls, zero.model.Config.Controls) {
		t.Errorf("controls = %v, zero-config = %v", res.Model.Config.Controls, zero.model.Config.Controls)
	}
	if !reflect.DeepEqual(res.Model.Config.Reachability, zero.model.Config.Reachability) {
		t.Errorf("reachability = %+v, zero-config = %+v", res.Model.Config.Reachability, zero.model.Config.Reachability)
	}
	for _, want := range []string{"gosec", "govulncheck", "semgrep", "gitleaks", "trivy-fs", "trivy-config"} {
		if !slices.Contains(usesNames(needs.Uses(reg, res.Model)), want) {
			t.Errorf("the descriptor init wrote does not run %s", want)
		}
	}
}

func TestRunInitStdout(t *testing.T) {
	var buf bytes.Buffer
	if err := runInit(t.TempDir(), initOptions{output: "-"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "project:") || !strings.Contains(buf.String(), "detect: true") {
		t.Errorf("stdout Saga looks wrong:\n%s", buf.String())
	}
}

func TestRunInitNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(out, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runInit(dir, initOptions{output: out}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected refuse-to-overwrite, got %v", err)
	}
	// --force overwrites.
	if err := runInit(dir, initOptions{output: out, force: true}, &bytes.Buffer{}); err != nil {
		t.Errorf("--force should overwrite: %v", err)
	}
}
