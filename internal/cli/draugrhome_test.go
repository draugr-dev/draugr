package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/draugrhome"
	"github.com/draugr-dev/draugr/internal/tools"
)

// draugrHomeWithGitleaks sets DRAUGR_HOME to a new directory and puts a gitleaks in its bin/, where
// `draugr tools install` would. HOME is another directory, so nothing can be found under ~/.draugr
// by accident. PATH is restored when the test ends, because execute changes the process's own.
func draugrHomeWithGitleaks(t *testing.T) (root, binary string) {
	t.Helper()
	t.Setenv("PATH", os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())
	root = t.TempDir()
	t.Setenv(draugrhome.EnvVar, root)
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	binary = filepath.Join(bin, "gitleaks")
	// #nosec G306 -- a stand-in tool, executable by design, in this test's own temp directory
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 8.30.1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root, binary
}

// Every command puts DRAUGR_HOME's bin/ ahead of PATH, so a scan runs the copy installed there,
// whatever else PATH holds.
func TestEveryCommandLooksInDraugrHomeFirst(t *testing.T) {
	root, binary := draugrHomeWithGitleaks(t)
	if code := execute(context.Background(), []string{"version"}); code != 0 {
		t.Fatalf("execute version = %d", code)
	}
	first := strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))[0]
	if want := filepath.Join(root, "bin"); first != want {
		t.Errorf("PATH starts with %q, want %q", first, want)
	}
	if got, err := exec.LookPath("gitleaks"); err != nil || got != binary {
		t.Errorf("gitleaks resolves to %q (%v), want %q", got, err, binary)
	}
}

// A relative DRAUGR_HOME stops the command before it runs, and PATH is left as it was: a scan that
// went on would run whatever PATH holds and read as though the variable had been honored.
func TestARelativeDraugrHomeStopsEveryCommand(t *testing.T) {
	t.Setenv("PATH", os.Getenv("PATH"))
	t.Setenv(draugrhome.EnvVar, "tools")
	before := os.Getenv("PATH")
	stderr := captureStderr(t)
	if code := execute(context.Background(), []string{"version"}); code != 1 {
		t.Errorf("execute version = %d, want 1", code)
	}
	if got := stderr(); !strings.Contains(got, "DRAUGR_HOME must be an absolute path") {
		t.Errorf("stderr = %q", got)
	}
	if os.Getenv("PATH") != before {
		t.Error("PATH changed under a refused DRAUGR_HOME")
	}
}

// doctor names the directory it looked in first, and says DRAUGR_HOME chose it, so a reader can tell
// why the paths in the table are not under ~/.draugr. The tool installed there is the one found.
func TestDoctorNamesTheDraugrHomeItUsed(t *testing.T) {
	root, binary := draugrHomeWithGitleaks(t)
	if code := execute(context.Background(), []string{"version"}); code != 0 {
		t.Fatalf("execute version = %d", code)
	}
	detect := func(ctx context.Context, tool tools.Tool) tools.Status {
		if tool.Binary != "gitleaks" {
			return tools.Status{Tool: tool}
		}
		return tools.Detect(ctx, tool, nil, nil)
	}
	var out bytes.Buffer
	_ = runDoctor(context.Background(), &out, builtins.Registry(), "", doctorRun{}, detect, nil)
	got := out.String()
	want := "TOOLS  looked for in " + filepath.Join(root, "bin") + " (DRAUGR_HOME), then on PATH"
	if !strings.Contains(got, want) {
		t.Errorf("the heading does not name DRAUGR_HOME's bin/, want %q in:\n%s", want, got)
	}
	if !strings.Contains(got, binary) {
		t.Errorf("gitleaks was not found at %s:\n%s", binary, got)
	}

	var doc bytes.Buffer
	_ = runDoctor(context.Background(), &doc, builtins.Registry(), "", doctorRun{json: true}, detect, nil)
	var report struct {
		ToolsDir string `json:"toolsDir"`
	}
	if err := json.Unmarshal(doc.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.ToolsDir != filepath.Join(root, "bin") {
		t.Errorf("toolsDir = %q, want %q", report.ToolsDir, filepath.Join(root, "bin"))
	}
}

// Without DRAUGR_HOME the heading names ~/.draugr/bin, as a reader would type it.
func TestDoctorNamesTheDefaultToolDirectory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(draugrhome.EnvVar, "")
	if got, want := toolsLookedFor(), "looked for in ~/.draugr/bin, then on PATH"; got != want {
		t.Errorf("toolsLookedFor() = %q, want %q", got, want)
	}
	// Where there is no directory to name, the heading names none rather than a guess.
	t.Setenv("HOME", "")
	if got := toolsLookedFor(); got != "" {
		t.Errorf("toolsLookedFor() with no home = %q", got)
	}
}
