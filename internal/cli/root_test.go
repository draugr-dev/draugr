package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

func TestExecuteUsesProcessArgs(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"draugr", "version"}
	if code := Execute(context.Background()); code != 0 {
		t.Errorf("Execute(version) exit = %d, want 0", code)
	}
}

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

func TestExecute(t *testing.T) {
	if code := execute(context.Background(), []string{"version"}); code != 0 {
		t.Errorf("execute version = %d, want 0", code)
	}
	if code := execute(context.Background(), []string{"definitely-not-a-command"}); code != 1 {
		t.Errorf("execute bogus = %d, want 1", code)
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
