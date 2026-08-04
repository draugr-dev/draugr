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

func TestVersionFlagMatchesTheVersionCommand(t *testing.T) {
	// `--version` is what every other CLI accepts — git, docker, kubectl, and every scanner
	// Draugr execs. Without it a container smoke test or a tool-cache probe gets a non-zero exit
	// on "unknown flag", which reads as a broken binary rather than a missing alias.
	run := func(args ...string) string {
		cmd := newRootCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute %v: %v", args, err)
		}
		return out.String()
	}
	flag, sub := run("--version"), run("version")
	if flag != sub {
		// Same bytes, so a script parsing one parses the other. Cobra's default template says
		// "draugr version X", which is neither.
		t.Errorf("--version printed %q, version printed %q", flag, sub)
	}
	if !strings.Contains(flag, "draugr") {
		t.Errorf("--version output = %q", flag)
	}
}
