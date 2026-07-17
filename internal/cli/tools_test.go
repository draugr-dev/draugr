package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/tools"
)

func TestRunToolsInstallSuccess(t *testing.T) {
	var out bytes.Buffer
	install := func(name string) (tools.Installed, error) {
		i := tools.Installed{Name: name, Version: "1.2.3", Path: "/home/u/.draugr/bin/" + name}
		if name == "trivy" { // trivy carries cosign provenance
			i.SignatureVerified = true
			i.ProvenanceNote = "cosign signature verified"
		}
		return i, nil
	}
	if err := runToolsInstall(&out, nil, []string{"trivy", "gitleaks"}, toolsInstallOptions{yes: true}, install); err != nil {
		t.Fatalf("runToolsInstall: %v", err)
	}
	s := out.String()
	for _, want := range []string{"✓ trivy 1.2.3", "sha256 + cosign verified", "✓ gitleaks 1.2.3", "sha256 verified"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n%s", want, s)
		}
	}
}

func TestProvenanceLabel(t *testing.T) {
	cases := []struct {
		in   tools.Installed
		want string
	}{
		{tools.Installed{SignatureVerified: true, ProvenanceNote: "cosign signature verified"}, "sha256 + cosign verified"},
		{tools.Installed{ProvenanceNote: "cosign not installed — skipped signature check"}, "sha256 verified; cosign not installed — skipped signature check"},
		{tools.Installed{}, "sha256 verified"},
	}
	for _, c := range cases {
		if got := provenanceLabel(c.in); got != c.want {
			t.Errorf("provenanceLabel(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRunToolsInstallPlanAndDryRun(t *testing.T) {
	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) { called = true; return tools.Installed{}, nil }
	if err := runToolsInstall(&out, nil, []string{"trivy", "cosign"}, toolsInstallOptions{dryRun: true}, install); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("--dry-run must not install anything")
	}
	s := out.String()
	for _, want := range []string{"Install plan", "trivy", "cosign", "scanner", "utility", "dry run"} {
		if !strings.Contains(s, want) {
			t.Errorf("plan output missing %q\n%s", want, s)
		}
	}
}

func TestRunToolsInstallInteractiveAbort(t *testing.T) {
	orig := isTTY
	isTTY = func(io.Reader) bool { return true }
	t.Cleanup(func() { isTTY = orig })

	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) { called = true; return tools.Installed{}, nil }
	// interactive + "n" → abort before installing.
	if err := runToolsInstall(&out, strings.NewReader("n\n"), []string{"trivy"}, toolsInstallOptions{}, install); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("a declined prompt must not install anything")
	}
	if !strings.Contains(out.String(), "Aborted") {
		t.Errorf("expected abort, got:\n%s", out.String())
	}
}

func TestRunToolsInstallSemgrepHint(t *testing.T) {
	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) { called = true; return tools.Installed{}, nil }
	if err := runToolsInstall(&out, nil, []string{"semgrep"}, toolsInstallOptions{yes: true}, install); err != nil {
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
	err := runToolsInstall(&out, nil, []string{"trivy"}, toolsInstallOptions{yes: true}, install)
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
	if err := runToolsInstall(&out, nil, nil, toolsInstallOptions{yes: true}, install); err != nil {
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
	for _, want := range []string{
		"TOOL", "CATEGORY", "CONTROLS", "PINNED",
		"trivy", "gitleaks", "semgrep", "git", "pipx",
		"secrets", // gitleaks → secrets control
		"utility", // cosign/git category
	} {
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
