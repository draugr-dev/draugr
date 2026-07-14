package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/tools"
)

func TestRunToolsInstallSuccess(t *testing.T) {
	var out bytes.Buffer
	install := func(name string) (tools.Installed, error) {
		return tools.Installed{Name: name, Version: "1.2.3", Path: "/home/u/.draugr/bin/" + name}, nil
	}
	if err := runToolsInstall(&out, []string{"trivy", "gitleaks"}, install); err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	s := out.String()
	for _, want := range []string{"✓ trivy 1.2.3", "✓ gitleaks 1.2.3", "sha256 ok"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n%s", want, s)
		}
	}
}

func TestRunToolsInstallSemgrepHint(t *testing.T) {
	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) { called = true; return tools.Installed{}, nil }
	if err := runToolsInstall(&out, []string{"semgrep"}, install); err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	if called {
		t.Error("semgrep should not go through the binary installer")
	}
	if !strings.Contains(out.String(), tools.SemgrepPipxCommand()) {
		t.Errorf("expected the pipx hint, got:\n%s", out.String())
	}
}

func TestRunToolsInstallFailure(t *testing.T) {
	var out bytes.Buffer
	install := func(string) (tools.Installed, error) {
		return tools.Installed{}, errors.New("boom")
	}
	err := runToolsInstall(&out, []string{"trivy"}, install)
	if err == nil {
		t.Fatal("expected error when an install fails")
	}
	if !strings.Contains(out.String(), "✗ trivy") {
		t.Errorf("output should flag the failed tool\n%s", out.String())
	}
}

func TestRunToolsInstallAllInstallsInstallable(t *testing.T) {
	var out bytes.Buffer
	var got []string
	install := func(name string) (tools.Installed, error) {
		got = append(got, name)
		return tools.Installed{Name: name, Version: "1.0.0", Path: "/x/" + name}, nil
	}
	// Empty names → install everything installable, then print the semgrep hint.
	if err := runToolsInstall(&out, nil, install); err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected installable tools to be installed")
	}
	for _, name := range got {
		if name == "semgrep" {
			t.Error("semgrep must not be passed to the binary installer")
		}
	}
	if !strings.Contains(out.String(), tools.SemgrepPipxCommand()) {
		t.Error("installing everything should still surface the semgrep hint")
	}
}

func TestRunToolsList(t *testing.T) {
	var out bytes.Buffer
	if err := runToolsList(context.Background(), &out); err != nil {
		t.Fatalf("runToolsList: %v", err)
	}
	s := out.String()
	for _, want := range []string{"TOOL", "PINNED", "trivy", "gitleaks", "semgrep", "git", "pipx"} {
		if !strings.Contains(s, want) {
			t.Errorf("list output missing %q\n%s", want, s)
		}
	}
}

func TestToolsCommandWiring(t *testing.T) {
	cmd := newToolsCommand()
	sub := map[string]bool{}
	for _, c := range cmd.Commands() {
		sub[c.Name()] = true
	}
	if !sub["install"] || !sub["list"] {
		t.Errorf("tools command missing subcommands: %v", sub)
	}
}
