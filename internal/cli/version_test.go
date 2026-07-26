package cli

import (
	"bytes"
	"strings"
	"testing"
)

// The version is this command's output, so it must go to stdout — `v=$(draugr version)` is the
// canonical usage. Cobra's cmd.Print* helpers write to stderr, which silently broke that.
func TestVersionGoesToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newVersionCommand()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(nil)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(stdout.String(), "draugr") {
		t.Errorf("version should be written to stdout, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("version should write nothing to stderr, got %q", stderr.String())
	}
}
