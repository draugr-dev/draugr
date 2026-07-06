package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute version: %v", err)
	}
	if !strings.Contains(out.String(), "draugr") {
		t.Fatalf("version output = %q, want it to contain %q", out.String(), "draugr")
	}
}

func TestUnknownCommandFails(t *testing.T) {
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"definitely-not-a-command"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for unknown command, got nil")
	}
}

func TestInvalidLogLevelFails(t *testing.T) {
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--log-level", "bogus", "version"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid log level, got nil")
	}
}
