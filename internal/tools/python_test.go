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

// stubPython puts a fake interpreter on PATH that mimics the two things installPython asks of it:
// reporting a version, and building a virtual environment with a pip and an entry point in it.
//
// A stub rather than the real thing because the real thing takes a minute and reaches the network,
// and what is under test is Draugr's sequence — resolve, build, install, link — not pip's.
//
// Installed under the newest name findPython looks for, so it wins over whatever real interpreter
// the machine has; and PATH is prepended rather than replaced, because the stub is shell and needs
// mkdir.
func stubPython(t *testing.T, pipScript string) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
case "$1" in
  -c) echo "3.14" ;;
  -m)
    mkdir -p "$3/bin"
    cat > "$3/bin/pip" <<'DRAUGRPIP'
` + pipScript + `
DRAUGRPIP
    chmod +x "$3/bin/pip"
    printf '#!/bin/sh\n' > "$3/bin/semgrep"
    chmod +x "$3/bin/semgrep"
    ;;
esac
`
	for _, name := range []string{"python3.14", "python3"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o750); err != nil { // #nosec G306 -- a stub has to run
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestInstallPythonBuildsAnEnvironmentAndLinksIt(t *testing.T) {
	stubPython(t, "#!/bin/sh\nexit 0")
	root := t.TempDir()

	shim, level, err := installPython(context.Background(), root, "semgrep",
		pythonInstallable["semgrep"], "1.173.0")
	if err != nil {
		t.Fatalf("installPython: %v", err)
	}
	// The pinned set applied, so the claim is the strongest one: every artifact matched a digest
	// recorded in this binary.
	if level != LevelPinned {
		t.Errorf("level = %q, want %q", level, LevelPinned)
	}
	if shim != filepath.Join(root, "bin", "semgrep") {
		t.Errorf("shim = %q", shim)
	}
	if _, err := os.Stat(shim); err != nil {
		t.Errorf("no shim was written: %v", err)
	}
	// The requirements installed from are the embedded ones, written where pip could read them —
	// not something assembled at run time.
	reqs, err := os.ReadFile(filepath.Join(pythonEnvDir(root, "semgrep"), "draugr-requirements.txt")) // #nosec G304 -- a path this test created
	if err != nil {
		t.Fatalf("no requirements file: %v", err)
	}
	if !strings.Contains(string(reqs), "semgrep==1.173.0") {
		t.Error("the requirements written are not the pinned ones")
	}
}

// A platform the pinned set does not cover still gets the tool, and says the claim is weaker.
//
// Claiming `pinned` there would describe evidence never gathered, and the point of recording a
// level at all is that a later reader can tell the two apart.
func TestInstallPythonDropsTheClaimWhenThePinsDoNotApply(t *testing.T) {
	// Fails the --require-hashes pass, succeeds the unpinned fallback.
	stubPython(t, `#!/bin/sh
for a in "$@"; do
  if [ "$a" = "--require-hashes" ]; then
    echo "hashes are required but this platform needs a different wheel" >&2
    exit 1
  fi
done
exit 0`)

	_, level, err := installPython(context.Background(), t.TempDir(), "semgrep",
		pythonInstallable["semgrep"], "1.173.0")
	if err != nil {
		t.Fatalf("installPython should fall back rather than fail: %v", err)
	}
	if level != LevelUnverified {
		t.Errorf("level = %q, want %q — nothing recorded in this binary checked that install",
			level, LevelUnverified)
	}
}

// Both passes failing is a failure, and the error carries what pip said rather than only that
// something exited non-zero.
func TestInstallPythonReportsWhatPipSaid(t *testing.T) {
	stubPython(t, "#!/bin/sh\necho \"no matching distribution\" >&2\nexit 1")

	_, _, err := installPython(context.Background(), t.TempDir(), "semgrep",
		pythonInstallable["semgrep"], "1.173.0")
	if err == nil {
		t.Fatal("a failed install was reported as a success")
	}
	if !strings.Contains(err.Error(), "no matching distribution") {
		t.Errorf("the error should relay what pip said: %v", err)
	}
}

// An interpreter that exists but is too old is named, rather than reported as absent.
//
// "No python3 found" sends somebody to install one they already have. The version they have is the
// fact that resolves it.
func TestFindPythonNamesAnInterpreterThatIsTooOld(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in -c) echo \"3.8\";; esac\n"
	if err := os.WriteFile(filepath.Join(dir, "python3"), []byte(script), 0o750); err != nil { // #nosec G306 -- a stub has to run
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	_, err := findPython(context.Background(), 10)
	if err == nil {
		t.Fatal("3.8 should not satisfy a 3.10 requirement")
	}
	if !strings.Contains(err.Error(), "3.8") {
		t.Errorf("the error should name the version found: %v", err)
	}
}

// An interpreter that cannot be run at all is skipped rather than crashing the search.
func TestPythonAtLeastOnSomethingThatIsNotPython(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "python3")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 3\n"), 0o750); err != nil { // #nosec G306 -- a stub has to run
		t.Fatal(err)
	}
	if ok, version := pythonAtLeast(context.Background(), path, 10); ok || version != "" {
		t.Errorf("a failing interpreter reported ok=%v version=%q", ok, version)
	}

	// And one that answers with something that is not a version.
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho banana\n"), 0o750); err != nil { // #nosec G306 -- a stub has to run
		t.Fatal(err)
	}
	if ok, version := pythonAtLeast(context.Background(), path, 10); ok {
		t.Errorf("%q was accepted as a version", version)
	}
	// A Python 2 answers in the same shape and must still be refused.
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 2.7\n"), 0o750); err != nil { // #nosec G306 -- a stub has to run
		t.Fatal(err)
	}
	if ok, _ := pythonAtLeast(context.Background(), path, 10); ok {
		t.Error("Python 2.7 was accepted")
	}
}

// run relays nothing extra when a command succeeds, and the command's own words when it fails.
func TestRunRelaysFailureOutput(t *testing.T) {
	if err := run(context.Background(), "true"); err != nil {
		t.Errorf("a successful command reported an error: %v", err)
	}
	err := run(context.Background(), "sh", "-c", "echo the reason >&2; exit 1")
	if err == nil {
		t.Fatal("a failing command reported success")
	}
	if !strings.Contains(err.Error(), "the reason") {
		t.Errorf("the error should carry the command's output: %v", err)
	}
	// A command that fails silently still reports the exit status rather than an empty message.
	if err := run(context.Background(), "sh", "-c", "exit 1"); err == nil {
		t.Error("a silent failure reported success")
	}
}

// The environment is rebuilt rather than installed over, so what is on disk is what was pinned.
func TestInstallPythonClearsTheOldEnvironment(t *testing.T) {
	stubPython(t, "#!/bin/sh\nexit 0")
	root := t.TempDir()
	envDir := pythonEnvDir(root, "semgrep")
	if err := os.MkdirAll(envDir, 0o750); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(envDir, "left-over-from-last-time")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := installPython(context.Background(), root, "semgrep",
		pythonInstallable["semgrep"], "1.173.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("the previous environment survived, so what is installed is not only what was pinned")
	}
}
