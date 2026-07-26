package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/version"
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

func TestVersionJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newVersionCommand()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version --json: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v (%q)", err, stdout.String())
	}
	// The point of the flag is that automation can read a field without regexing prose.
	for _, key := range []string{"version", "commit", "built", "go"} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing %q in %v", key, got)
		}
	}
	if got["version"] != version.Version {
		t.Errorf("version = %q, want %q", got["version"], version.Version)
	}
	if stderr.Len() != 0 {
		t.Errorf("nothing should go to stderr, got %q", stderr.String())
	}
}
