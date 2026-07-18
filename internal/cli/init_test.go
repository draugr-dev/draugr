package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInitWritesFileWithDetection(t *testing.T) {
	dir := t.TempDir()
	// Go + Dockerfile → gosec hint + images stub.
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "draugr.saga.yaml")
	var buf bytes.Buffer
	if err := runInit(dir, initOptions{output: out}, &buf); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out) //nolint:gosec // out is a test-controlled temp path
	if err != nil {
		t.Fatalf("expected %s written: %v", out, err)
	}
	s := string(data)
	for _, want := range []string{"Detected: Go", "scanners: [semgrep, gosec]", "images:", "sca:", "url: ."} {
		if !strings.Contains(s, want) {
			t.Errorf("generated Saga missing %q:\n%s", want, s)
		}
	}
	// The generated Saga must be valid.
	if _, err := loadSaga(out); err != nil {
		t.Errorf("generated Saga is not valid: %v", err)
	}
}

func TestRunInitStdout(t *testing.T) {
	var buf bytes.Buffer
	if err := runInit(t.TempDir(), initOptions{output: "-"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "release:") || !strings.Contains(buf.String(), "controllers:") {
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
