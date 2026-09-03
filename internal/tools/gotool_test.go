package tools

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeGo writes an executable standing in for the Go toolchain. `go version` prints what the test
// asks for; `go install` writes a binary into GOBIN unless the test wants it to fail, so the
// verified/fallback split can be exercised without a network.
func fakeGo(t *testing.T, version string, installFails bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "go")
	fail := "0"
	if installFails {
		fail = "1"
	}
	script := `#!/bin/sh
case "$1" in
version) echo ` + strconv.Quote("go version "+version+" linux/amd64") + ` ;;
install)
  # A verified run is the one this code sets GOSUMDB for. Refuse it when the test asks, so the
  # fallback path is reached the way an unreachable checksum database would reach it.
  if [ "` + fail + `" = "1" ] && [ "$GOSUMDB" = "sum.golang.org" ]; then
    echo "checksum database unreachable" >&2; exit 1
  fi
  mkdir -p "$GOBIN" && printf 'binary' > "$GOBIN/govulncheck" ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- must execute
		t.Fatal(err)
	}
	return path
}

func TestEveryGoToolHasAPinnedVersion(t *testing.T) {
	for name := range goInstallable {
		if goVersions[name] == "" {
			t.Errorf("%s is installable but has no pinned version", name)
		}
		if GoVersion(name) != goVersions[name] {
			t.Errorf("GoVersion(%s) disagrees with the pin", name)
		}
	}
	if GoVersion("not-a-tool") != "" {
		t.Error("an unknown tool should have no pinned version")
	}
	if _, ok := GoTool("not-a-tool"); ok {
		t.Error("GoTool should not report an unknown tool")
	}
}

// TestGoToolsAreInstallable is the check that keeps a new install path reachable. A tool missing
// here is one `tools install` provisions and every caller believes it cannot.
func TestGoToolsAreInstallable(t *testing.T) {
	listed := make(map[string]bool)
	for _, n := range Installable() {
		listed[n] = true
	}
	for name := range goInstallable {
		if !listed[name] {
			t.Errorf("%s is missing from Installable()", name)
		}
		if ManagedVersion(name) != goVersions[name] {
			t.Errorf("ManagedVersion(%s) = %q, want the pin %q",
				name, ManagedVersion(name), goVersions[name])
		}
	}
}

// TestGovulncheckVersionReadsTheScannerNotTheToolchain is the point of the extractor: the probe's
// first line names Go, and taking the first version-looking token reports the toolchain as the
// scanner's version — a number that is real, plausible, and about something else.
func TestGovulncheckVersionReadsTheScannerNotTheToolchain(t *testing.T) {
	out := "Go: go1.26.7\nScanner: govulncheck@v1.7.0\nDB: https://vuln.go.dev\n" +
		"DB updated: 2026-09-02 19:12:04 +0000 UTC\n"
	if got := GovulncheckVersion([]byte(out)); got != "1.7.0" {
		t.Errorf("GovulncheckVersion = %q, want 1.7.0", got)
	}
	if got := semverRE.FindString(out); got != "1.26.7" {
		t.Fatalf("the generic parser should still take the Go version (%q) — "+
			"if it does not, this extractor may no longer be needed", got)
	}
	if got := GovulncheckVersion([]byte("Go: go1.26.7\n")); got != "" {
		t.Errorf("output with no Scanner line should yield nothing, got %q", got)
	}
}

func TestGoAtLeastReadsTheToolchainVersion(t *testing.T) {
	for _, c := range []struct {
		name, output string
		ok           bool
		found        string
	}{
		{"new enough", "go1.26.6", true, "1.26.6"},
		{"exactly the minimum", "go1.21.0", true, "1.21.0"},
		{"too old", "go1.20.14", false, "1.20.14"},
		{"unparseable", "banana", false, "banana"},
	} {
		t.Run(c.name, func(t *testing.T) {
			goBin := fakeGo(t, c.output, false)
			ok, found := goAtLeast(t.Context(), goBin, minGoMinor)
			if ok != c.ok || found != c.found {
				t.Errorf("goAtLeast = %v, %q; want %v, %q", ok, found, c.ok, c.found)
			}
		})
	}
}

// TestFindGoExplainsWhatToDo pins the two failures a user can act on. Both must name a way
// forward: this is a tool Draugr can install, so "not found" alone leaves the reader with a
// missing scanner and no next step.
func TestFindGoExplainsWhatToDo(t *testing.T) {
	t.Run("no go", func(t *testing.T) {
		stubLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
		_, err := findGo(t.Context(), "govulncheck")
		if err == nil {
			t.Fatal("a missing Go toolchain must be an error, not a silent skip")
		}
		if !strings.Contains(err.Error(), "golang.org/x/vuln/cmd/govulncheck") {
			t.Errorf("the error should offer a way forward: %v", err)
		}
	})

	t.Run("go too old", func(t *testing.T) {
		goBin := fakeGo(t, "go1.20.14", false)
		stubLookPath(t, func(string) (string, error) { return goBin, nil })
		_, err := findGo(t.Context(), "govulncheck")
		if err == nil {
			t.Fatal("a Go too old to fetch the module's toolchain must be an error")
		}
		if !strings.Contains(err.Error(), "1.20.14") || !strings.Contains(err.Error(), "21") {
			t.Errorf("the error should name the version found and the one needed: %v", err)
		}
	})
}

func TestInstallGoBuildsIntoDraugrsOwnBinAndReportsPinned(t *testing.T) {
	goBin := fakeGo(t, "go1.26.6", false)
	stubLookPath(t, func(string) (string, error) { return goBin, nil })

	root := t.TempDir()
	path, level, err := installGo(t.Context(), root, "govulncheck",
		goInstallable["govulncheck"], govulncheckVersion)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "bin", "govulncheck"); path != want {
		t.Errorf("installed to %q, want %q", path, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the binary is not where it was reported: %v", err)
	}
	if level != LevelPinned {
		t.Errorf("level = %q, want %q — the checksum database verified this build",
			level, LevelPinned)
	}
}

// TestInstallGoDropsToUnverifiedWhenTheChecksumDatabaseIsUnreachable is the honesty check:
// falling back keeps the tool installable on an air-gapped host, and the level has to say that
// nothing this code set verified what was built.
func TestInstallGoDropsToUnverifiedWhenTheChecksumDatabaseIsUnreachable(t *testing.T) {
	goBin := fakeGo(t, "go1.26.6", true)
	stubLookPath(t, func(string) (string, error) { return goBin, nil })

	root := t.TempDir()
	_, level, err := installGo(t.Context(), root, "govulncheck",
		goInstallable["govulncheck"], govulncheckVersion)
	if err != nil {
		t.Fatal(err)
	}
	if level != LevelUnverified {
		t.Errorf("level = %q, want %q", level, LevelUnverified)
	}
}

// TestInstallGoReportsAModuleThatBuildsNothing guards the half-install: `go install` can succeed
// and produce no command, and reporting a path that is not there sends the reader looking at PATH.
func TestInstallGoReportsAModuleThatBuildsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go")
	script := "#!/bin/sh\ncase \"$1\" in version) echo 'go version go1.26.6 linux/amd64' ;; esac\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- must execute
		t.Fatal(err)
	}
	stubLookPath(t, func(string) (string, error) { return path, nil })

	_, _, err := installGo(t.Context(), t.TempDir(), "govulncheck",
		goInstallable["govulncheck"], govulncheckVersion)
	if err == nil {
		t.Fatal("a build producing no command must be an error")
	}
	if !strings.Contains(err.Error(), "no \"govulncheck\" command") {
		t.Errorf("the error should name what is missing: %v", err)
	}
}

func TestRunEnvReportsTheCommandsOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noisy")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'it went wrong' >&2\nexit 3\n"), 0o700); err != nil { // #nosec G306 -- must execute
		t.Fatal(err)
	}
	err := runEnv(t.Context(), os.Environ(), path)
	if err == nil {
		t.Fatal("a non-zero exit must be an error")
	}
	if !strings.Contains(err.Error(), "it went wrong") {
		t.Errorf("the error should carry the command's own output: %v", err)
	}
}

// TestGoAtLeastOnOutputItCannotRead covers the answers that are not a version: a toolchain that
// fails to run, output that is not `go version …`, and a major that is not 1. Reporting any of
// them as new enough would let the install proceed against something nothing checked.
func TestGoAtLeastOnOutputItCannotRead(t *testing.T) {
	t.Run("go version fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "go")
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil { // #nosec G306 -- must execute
			t.Fatal(err)
		}
		if ok, found := goAtLeast(t.Context(), path, minGoMinor); ok || found != "unknown" {
			t.Errorf("goAtLeast = %v, %q; want false, \"unknown\"", ok, found)
		}
	})

	t.Run("output is not go version", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "go")
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0o700); err != nil { // #nosec G306 -- must execute
			t.Fatal(err)
		}
		if ok, found := goAtLeast(t.Context(), path, minGoMinor); ok || found != "unknown" {
			t.Errorf("goAtLeast = %v, %q; want false, \"unknown\"", ok, found)
		}
	})

	t.Run("a Go 2 clears any 1.x floor", func(t *testing.T) {
		goBin := fakeGo(t, "go2.0.0", false)
		if ok, found := goAtLeast(t.Context(), goBin, minGoMinor); !ok || found != "2.0.0" {
			t.Errorf("goAtLeast = %v, %q; want true, \"2.0.0\"", ok, found)
		}
	})

	t.Run("a major below 1", func(t *testing.T) {
		goBin := fakeGo(t, "go0.9", false)
		if ok, _ := goAtLeast(t.Context(), goBin, minGoMinor); ok {
			t.Error("a major below 1 is not new enough")
		}
	})

	t.Run("no minor at all", func(t *testing.T) {
		goBin := fakeGo(t, "go1", false)
		if ok, _ := goAtLeast(t.Context(), goBin, minGoMinor); ok {
			t.Error("a version with no readable minor is not new enough")
		}
	})
}

func TestRunEnvOnSilentAndNoisyFailures(t *testing.T) {
	t.Run("no output at all", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "silent")
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 2\n"), 0o700); err != nil { // #nosec G306 -- must execute
			t.Fatal(err)
		}
		err := runEnv(t.Context(), os.Environ(), path)
		if err == nil {
			t.Fatal("a non-zero exit must be an error even with nothing to say")
		}
	})

	// A toolchain can print a great deal on failure, and an error nobody can read is one nobody
	// acts on. The cap is the same one the npm path uses.
	t.Run("output is truncated", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "verbose")
		script := "#!/bin/sh\nawk 'BEGIN{for(i=0;i<400;i++) print \"a line of build output\"}'\nexit 1\n"
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- must execute
			t.Fatal(err)
		}
		err := runEnv(t.Context(), os.Environ(), path)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.HasSuffix(err.Error(), "…") {
			t.Errorf("long output should be truncated with an ellipsis: %q", err)
		}
		if len(err.Error()) > 2200 {
			t.Errorf("the error is %d bytes; the cap should keep it near 2048", len(err.Error()))
		}
	})
}

// TestInstallGoReportsBothAttemptsFailing keeps the fallback from hiding the real reason: when
// neither the verified nor the ambient run works, the error names what was being installed.
func TestInstallGoReportsBothAttemptsFailing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go")
	script := "#!/bin/sh\ncase \"$1\" in\nversion) echo 'go version go1.26.6 linux/amd64' ;;\n" +
		"install) echo 'module not found' >&2; exit 1 ;;\nesac\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- must execute
		t.Fatal(err)
	}
	stubLookPath(t, func(string) (string, error) { return path, nil })

	_, _, err := installGo(t.Context(), t.TempDir(), "govulncheck",
		goInstallable["govulncheck"], govulncheckVersion)
	if err == nil {
		t.Fatal("both attempts failing must be an error")
	}
	if !strings.Contains(err.Error(), "golang.org/x/vuln/cmd/govulncheck@v"+govulncheckVersion) {
		t.Errorf("the error should name what it was installing: %v", err)
	}
}

// TestInstallGoToolRecordsWhatEndedUpOnPath is the node/python equivalent for the Go path: an
// empty version asks for the pinned one, and the binary that lands is the file the attestation is
// about. Recording a digest of anything else would attest something nobody runs.
func TestInstallGoToolRecordsWhatEndedUpOnPath(t *testing.T) {
	root := t.TempDir()
	destDir := filepath.Join(root, "bin")
	goBin := fakeGo(t, "go1.26.6", false)
	stubLookPath(t, func(string) (string, error) { return goBin, nil })

	// An empty version asks for the pinned one, which is how `tools install govulncheck` arrives.
	got, err := installGoTool(t.Context(), "govulncheck", "", destDir,
		goInstallable["govulncheck"])
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != govulncheckVersion {
		t.Errorf("version = %q, want the pinned %q", got.Version, govulncheckVersion)
	}
	if got.Name != "govulncheck" {
		t.Errorf("name = %q", got.Name)
	}
	if want := filepath.Join(root, "bin", "govulncheck"); got.Path != want {
		t.Errorf("path = %q, want %q", got.Path, want)
	}
	sum, err := fileSHA256(got.Path)
	if err != nil {
		t.Fatalf("the recorded path is not a readable file: %v", err)
	}
	if sum == "" {
		t.Error("the binary produced no digest, so nothing could attest it")
	}
}

// An explicit version overrides the pin — the path `tools install govulncheck --version` takes.
func TestInstallGoToolTakesAnExplicitVersion(t *testing.T) {
	goBin := fakeGo(t, "go1.26.6", false)
	stubLookPath(t, func(string) (string, error) { return goBin, nil })

	got, err := installGoTool(t.Context(), "govulncheck", "1.6.0",
		filepath.Join(t.TempDir(), "bin"), goInstallable["govulncheck"])
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "1.6.0" {
		t.Errorf("version = %q, want the requested 1.6.0", got.Version)
	}
}
