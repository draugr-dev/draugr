package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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
		"Tool", "Category", "Controls", "Pinned",
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

// A misspelled tool used to be rendered as a row of dashes in the install plan, followed by a
// confirmation prompt. It's a typo — say so and stop.
func TestToolsInstallRejectsUnknownTool(t *testing.T) {
	var out bytes.Buffer
	called := false
	install := func(string) (tools.Installed, error) {
		called = true
		return tools.Installed{}, nil
	}
	err := runToolsInstall(&out, nil, []string{"notarealtool"}, toolsInstallOptions{yes: true}, install)
	if err == nil {
		t.Fatal("an unknown tool should be an error")
	}
	if called {
		t.Error("nothing should be installed when a name is unknown")
	}
	if !strings.Contains(err.Error(), "installable:") {
		t.Errorf("the error should list what can be installed: %v", err)
	}
	if strings.Contains(out.String(), "Install plan") {
		t.Error("no plan should be printed for an unknown tool")
	}
}

func TestToolsInstallSuggestsNearMiss(t *testing.T) {
	err := runToolsInstall(&bytes.Buffer{}, nil, []string{"trivvy"}, toolsInstallOptions{yes: true},
		func(string) (tools.Installed, error) { return tools.Installed{}, nil })
	if err == nil || !strings.Contains(err.Error(), `did you mean "trivy"`) {
		t.Errorf("expected a suggestion for a near-miss, got %v", err)
	}
}

// One bad name fails the whole command: half-installing after a typo is the surprising outcome.
func TestToolsInstallRejectsMixedValidAndInvalid(t *testing.T) {
	installed := 0
	err := runToolsInstall(&bytes.Buffer{}, nil, []string{"trivy", "nope"}, toolsInstallOptions{yes: true},
		func(string) (tools.Installed, error) { installed++; return tools.Installed{}, nil })
	if err == nil {
		t.Fatal("a mix containing an unknown tool should fail")
	}
	if installed != 0 {
		t.Errorf("installed %d tool(s); a typo should stop the whole command", installed)
	}
}

func TestClosestName(t *testing.T) {
	known := []string{"trivy", "gitleaks", "gosec", "cosign"}
	if got := closestName("trivvy", known); got != "trivy" {
		t.Errorf("closestName(trivvy) = %q", got)
	}
	if got := closestName("gitleak", known); got != "gitleaks" {
		t.Errorf("closestName(gitleak) = %q", got)
	}
	// Nothing close enough shouldn't produce a misleading suggestion.
	if got := closestName("kubernetes", known); got != "" {
		t.Errorf("closestName(kubernetes) = %q, want no suggestion", got)
	}
}

const toolsSagaTwoControls = `release: {name: t, version: "1.0"}
config:
  controllers:
    sca: {enabled: true}
    secrets: {enabled: true}
components:
  - name: c
    repositories: [{url: "https://example.com/x.git"}]
`

// The point of the flag: install what this project runs, not the catalogue. On a security tool
// every binary put on PATH is one more thing to trust and patch, so the smaller set is the
// defensible one.
func TestInstallNamesFromSaga(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	got, err := installNames(&out, nil, toolsInstallOptions{saga: writeSaga(t, toolsSagaTwoControls)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"gitleaks", "trivy"}) {
		t.Errorf("names = %v, want [gitleaks trivy]", got)
	}
	if len(got) >= len(tools.Installable()) {
		t.Error("a scoped install that installs everything has done nothing")
	}
	// git is needed and cannot be provisioned. Installing the rest and reporting success would
	// leave someone one failed scan away from finding that out.
	if !strings.Contains(out.String(), "git") || !strings.Contains(out.String(), "cannot provision") {
		t.Errorf("the gap should be reported, got %q", out.String())
	}
}

// Without the flag nothing changes — a pipeline that provisions the catalogue keeps doing so.
func TestInstallNamesWithoutSagaIsUnchanged(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	got, err := installNames(&out, nil, toolsInstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("names = %v, want none — an empty list means the whole catalogue downstream", got)
	}

	named, err := installNames(&out, []string{"trivy"}, toolsInstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(named, []string{"trivy"}) {
		t.Errorf("explicit names should pass through, got %v", named)
	}
}

// Two ways of saying what to install, pointing at different sets. Guessing which one was meant
// is how you install the wrong thing quietly.
func TestInstallNamesRejectsSagaWithExplicitTools(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	_, err := installNames(&out, []string{"trivy"}, toolsInstallOptions{saga: writeSaga(t, toolsSagaTwoControls)})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "trivy") {
		t.Errorf("the error should name what was asked for, got: %v", err)
	}
}

func TestInstallNamesReportsABadSaga(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if _, err := installNames(&out, nil, toolsInstallOptions{saga: "/nonexistent/saga.yaml"}); err == nil {
		t.Error("an unreadable descriptor must fail rather than installing everything")
	}
}

// The note is the compromise that lets the default stay as it was: behaviour unchanged, the
// better option surfaced where it is relevant. Its number has to match what --saga would
// actually install, or it promises a saving the flag does not deliver.
func TestNoteDescriptorInWorkingDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var out bytes.Buffer
	noteDescriptorInWorkingDir(&out)
	if out.String() != "" {
		t.Errorf("no descriptor here, so nothing to note; got %q", out.String())
	}

	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte(toolsSagaTwoControls), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	noteDescriptorInWorkingDir(&out)
	// Two of the catalogue, not three: git is needed but cannot be provisioned, and counting it
	// would advertise a saving --saga does not make.
	want := fmt.Sprintf("would install 2 of these %d tools", len(tools.Installable()))
	if !strings.Contains(out.String(), want) {
		t.Errorf("note = %q, want it to contain %q", out.String(), want)
	}

	// An unreadable descriptor is scan's problem to report, not a reason to fail provisioning.
	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte("{{not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	noteDescriptorInWorkingDir(&out)
	if out.String() != "" {
		t.Errorf("a broken descriptor should be left to scan and doctor, got %q", out.String())
	}
}

func TestPluralThem(t *testing.T) {
	t.Parallel()
	if got := pluralThem(1); got != "it" {
		t.Errorf("pluralThem(1) = %q", got)
	}
	if got := pluralThem(2); got != "them" {
		t.Errorf("pluralThem(2) = %q", got)
	}
}
