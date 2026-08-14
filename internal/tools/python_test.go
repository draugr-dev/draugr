package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every Python-packaged tool has pins built in, at the version it is pinned to.
//
// The drift this catches is the obvious one: bump the version constant, forget to regenerate the
// requirements. Nothing would fail at build time — the install would simply resolve a different
// version from the one Draugr reports, and record it as `pinned` while the pins described something
// else. A wrong provenance claim is worse than none.
func TestEveryPythonToolHasPinsAtItsVersion(t *testing.T) {
	for name, spec := range pythonInstallable {
		version, ok := pythonVersions[name]
		if !ok || version == "" {
			t.Errorf("%s is installable as a Python package but has no pinned version", name)
			continue
		}
		data, err := pythonPins.ReadFile("pythonpins/" + spec.Pins + ".txt")
		if err != nil {
			t.Errorf("%s: no pins are built into this binary: %v", name, err)
			continue
		}
		pins := string(data)
		want := spec.Package + "==" + version
		if !strings.Contains(pins, want) {
			t.Errorf("%s: the pins do not contain %q — regenerate with\n"+
				"    python3 internal/tools/pythonpins/generate.py %s %s", name, want, name, version)
		}
		// Every line that names a package must carry a hash, or --require-hashes rejects the file
		// wholesale and every install silently takes the unpinned fallback.
		for _, line := range strings.Split(pins, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "--hash") ||
				strings.HasSuffix(line, "\\") {
				continue
			}
			t.Errorf("%s: %q has no hash continuation, so --require-hashes would reject the file",
				name, line)
		}
	}
}

func TestPythonToolLookup(t *testing.T) {
	if _, ok := PythonTool("semgrep"); !ok {
		t.Error("semgrep should be obtainable as a Python package")
	}
	if _, ok := PythonTool("trivy"); ok {
		t.Error("trivy is a release binary, not a Python package")
	}
	// Both routes count as provisionable, which is what decides whether `doctor` tells somebody to
	// run `tools install` or to go and find the tool themselves.
	for _, tool := range []string{"semgrep", "trivy"} {
		if !Provisionable(tool) {
			t.Errorf("%s should be provisionable", tool)
		}
	}
	if Provisionable("mend") {
		t.Error("mend is proprietary and Draugr cannot provision it")
	}
}

// semgrep has to be in the list `tools install` offers, or it is installable and undiscoverable.
func TestInstallableIncludesPythonTools(t *testing.T) {
	var found bool
	for _, name := range Installable() {
		if name == "semgrep" {
			found = true
		}
	}
	if !found {
		t.Errorf("Installable() = %v, missing semgrep", Installable())
	}
}

// The shim puts the environment's own bin first on PATH.
//
// Semgrep's launcher resolves a `semgrep` from PATH ahead of the one beside it, so a stale copy
// elsewhere — a pipx install from before this existed — answers instead, and reports its own
// version while Draugr reports the one it installed. Measured: with 1.169.0 on PATH the venv's
// 1.173.0 reported itself as 1.169.0.
func TestShimPutsItsOwnEnvironmentFirst(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "venv", "semgrep")
	if err := os.MkdirAll(filepath.Join(envDir, "bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(envDir, "bin", "semgrep")
	if err := os.WriteFile(entry, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(dir, "bin", "semgrep")
	if err := linkPythonEntryPoint(envDir, "semgrep", shim); err != nil {
		t.Fatal(err)
	}

	script, err := os.ReadFile(shim) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	body := string(script)
	if !strings.Contains(body, "PATH="+filepath.Join(envDir, "bin")+":$PATH") {
		t.Errorf("the shim does not put its own bin first:\n%s", body)
	}
	if !strings.Contains(body, "exec "+entry) {
		t.Errorf("the shim does not exec the environment's entry point:\n%s", body)
	}
	info, err := os.Stat(shim)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("the shim is not executable: %v", info.Mode())
	}
}

// A package that installs but provides no command is a half-install that looks whole.
func TestShimRefusesWhenThereIsNoEntryPoint(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "venv", "nothing")
	if err := os.MkdirAll(filepath.Join(envDir, "bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	err := linkPythonEntryPoint(envDir, "nothing", filepath.Join(dir, "bin", "nothing"))
	if err == nil {
		t.Fatal("a missing entry point was accepted")
	}
	if !strings.Contains(err.Error(), "provides no") {
		t.Errorf("the error should say what is missing: %v", err)
	}
}

func TestPythonAtLeast(t *testing.T) {
	// The interpreter running the tests is a real one, which is the only version this can assert
	// against without shipping a fixture interpreter.
	python, err := lookPythonForTest()
	if err != nil {
		t.Skip("no python3 on PATH")
	}
	if ok, version := pythonAtLeast(context.Background(), python, 3); !ok {
		t.Errorf("python3 %s reported as older than 3.3", version)
	}
	// Nothing is new enough for a minor that does not exist yet, and the version still comes back
	// so the error can name what was found.
	ok, version := pythonAtLeast(context.Background(), python, 99)
	if ok {
		t.Error("python3 reported as at least 3.99")
	}
	if version == "" {
		t.Error("the version should be reported even when it is too old, so the error can name it")
	}
}

// A machine with no usable interpreter gets one sentence naming what to install, rather than a
// resolver failure forty lines deep.
func TestFindPythonSaysWhatIsMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := findPython(context.Background(), 10)
	if err == nil {
		t.Fatal("expected an error with no python on PATH")
	}
	for _, want := range []string{"python 3.10", "PATH"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should mention %q: %v", want, err)
		}
	}
}

// lookPythonForTest finds any python3, so the version helpers can be exercised against a real one.
func lookPythonForTest() (string, error) { return execLookPath("python3") }
