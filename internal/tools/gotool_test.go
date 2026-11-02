package tools

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// fakeGo writes an executable standing in for the Go toolchain. `go version` prints what the test
// asks for, and so does `go env GOVERSION` when it is asked under GOTOOLCHAIN=local; `go install`
// writes a binary into GOBIN unless the test wants it to fail, so the verified/fallback split can
// be exercised without a network. The binary holds the GOTOOLCHAIN the build ran under.
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
env)
  # Without GOTOOLCHAIN=local the go command reports the toolchain it would switch to, which is
  # not the Go on PATH, so a question asked the wrong way gets a different answer.
  if [ "$GOTOOLCHAIN" = "local" ]; then echo ` + strconv.Quote(version) + `; else echo go9.9.9; fi ;;
install)
  # A verified run is the one this code sets GOSUMDB for. Refuse it when the test asks, so the
  # fallback path is reached the way an unreachable checksum database would reach it.
  if [ "` + fail + `" = "1" ] && [ "$GOSUMDB" = "sum.golang.org" ]; then
    echo "checksum database unreachable" >&2; exit 1
  fi
  mkdir -p "$GOBIN" && printf 'GOTOOLCHAIN=%s' "$GOTOOLCHAIN" > "$GOBIN/govulncheck" ;;
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
// scanner's version. A number that is real, plausible, and about something else.
func TestGovulncheckVersionReadsTheScannerNotTheToolchain(t *testing.T) {
	out := "Go: go1.26.7\nScanner: govulncheck@v1.7.0\nDB: https://vuln.go.dev\n" +
		"DB updated: 2026-09-02 19:12:04 +0000 UTC\n"
	if got := GovulncheckVersion([]byte(out)); got != "1.7.0" {
		t.Errorf("GovulncheckVersion = %q, want 1.7.0", got)
	}
	if got := semverRE.FindString(out); got != "1.26.7" {
		t.Fatalf("the generic parser should still take the Go version (%q), "+
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

// noUserToolchain clears GOTOOLCHAIN for the test. The go command sets it in the environment of a
// toolchain it switches to, so a test run under a switched toolchain would otherwise inherit one.
func noUserToolchain(t *testing.T) {
	t.Helper()
	t.Setenv("GOTOOLCHAIN", "")
}

// builtUnder is the GOTOOLCHAIN the fake go install ran under, which it writes into the binary.
func builtUnder(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a file under the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(string(raw), "GOTOOLCHAIN=")
}

func TestInstallGoBuildsIntoDraugrsOwnBinAndReportsPinned(t *testing.T) {
	noUserToolchain(t)
	goBin := fakeGo(t, "go1.26.6", false)
	stubLookPath(t, func(string) (string, error) { return goBin, nil })

	root := t.TempDir()
	built, err := installGo(t.Context(), root, "govulncheck",
		goInstallable["govulncheck"], govulncheckVersion)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "bin", "govulncheck"); built.path != want {
		t.Errorf("installed to %q, want %q", built.path, want)
	}
	if _, err := os.Stat(built.path); err != nil {
		t.Errorf("the binary is not where it was reported: %v", err)
	}
	if built.level != LevelPinned {
		t.Errorf("level = %q, want %q, the checksum database verified this build",
			built.level, LevelPinned)
	}
}

// The Go that builds govulncheck decides which modules it can load, so the build runs under the
// newer of the Go on PATH and the pin, or under the release the environment names, and reports the
// release it ran.
func TestInstallGoBuildsWithTheNewerOfThePinAndTheLocalGo(t *testing.T) {
	for _, tc := range []struct {
		name, local, user  string
		wantEnv, wantBuilt string
	}{
		{"the local Go is older than the pin", "go1.26.10", "", govulncheckToolchain, govulncheckToolchain},
		{"the local Go is the pin", govulncheckToolchain, "", "local", govulncheckToolchain},
		{"the local Go is newer than the pin", "go1.99.1", "", "local", "go1.99.1"},
		{"the environment names a release", "go1.26.10", "go1.98.0", "go1.98.0", "go1.98.0"},
		{"the environment names a policy", "go1.26.10", "local", govulncheckToolchain, govulncheckToolchain},
		{"the environment names a minimum", "go1.26.10", "go1.98.0+auto", govulncheckToolchain, govulncheckToolchain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOTOOLCHAIN", tc.user)
			goBin := fakeGo(t, tc.local, false)
			stubLookPath(t, func(string) (string, error) { return goBin, nil })

			built, err := installGo(t.Context(), t.TempDir(), "govulncheck",
				goInstallable["govulncheck"], govulncheckVersion)
			if err != nil {
				t.Fatal(err)
			}
			if got := builtUnder(t, built.path); got != tc.wantEnv {
				t.Errorf("built under GOTOOLCHAIN=%q, want %q", got, tc.wantEnv)
			}
			if built.toolchain != tc.wantBuilt {
				t.Errorf("reported %q as the Go that built it, want %q", built.toolchain, tc.wantBuilt)
			}
		})
	}
}

// A Go whose version cannot be asked is not taken to be new enough, so the build runs under the pin.
func TestInstallGoBuildsWithThePinWhenTheLocalGoCannotSay(t *testing.T) {
	noUserToolchain(t)
	goBin := fakeGo(t, "not-a-version", false)
	if got, release := buildToolchain(t.Context(), goBin, govulncheckToolchain); got != govulncheckToolchain || release != govulncheckToolchain {
		t.Errorf("buildToolchain = %q, %q; want the pin", got, release)
	}
	if got := localGoVersion(t.Context(), filepath.Join(t.TempDir(), "no-go")); got != "" {
		t.Errorf("a go that does not run reported %q", got)
	}
}

// TestInstallGoDropsToUnverifiedWhenTheChecksumDatabaseIsUnreachable is the honesty check:
// falling back keeps the tool installable on an air-gapped host, and the level has to say that
// nothing this code set verified what was built. The fallback builds with the same Go, or it would
// build with whatever is on PATH and record the pin.
func TestInstallGoDropsToUnverifiedWhenTheChecksumDatabaseIsUnreachable(t *testing.T) {
	noUserToolchain(t)
	goBin := fakeGo(t, "go1.26.6", true)
	stubLookPath(t, func(string) (string, error) { return goBin, nil })

	root := t.TempDir()
	built, err := installGo(t.Context(), root, "govulncheck",
		goInstallable["govulncheck"], govulncheckVersion)
	if err != nil {
		t.Fatal(err)
	}
	if built.level != LevelUnverified {
		t.Errorf("level = %q, want %q", built.level, LevelUnverified)
	}
	if got := builtUnder(t, built.path); got != govulncheckToolchain {
		t.Errorf("the fallback built under GOTOOLCHAIN=%q, want the pin %q", got, govulncheckToolchain)
	}
}

// The verified environment enforces the checksum database and the fallback leaves the ambient
// settings, and both carry the toolchain and Draugr's bin directory. Later entries win in os/exec,
// so each is checked by the value it ends on.
func TestGoInstallEnv(t *testing.T) {
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("GOFLAGS", "-mod=mod")
	last := func(env []string, key string) string {
		v := ""
		for _, kv := range env {
			if k, val, ok := strings.Cut(kv, "="); ok && k == key {
				v = val
			}
		}
		return v
	}
	verified := goInstallEnv("/bin-dir", "go1.27.3", true)
	for key, want := range map[string]string{
		"GOBIN": "/bin-dir", "GOTOOLCHAIN": "go1.27.3", "GOSUMDB": "sum.golang.org", "GOFLAGS": "",
	} {
		if got := last(verified, key); got != want {
			t.Errorf("verified %s = %q, want %q", key, got, want)
		}
	}
	fallback := goInstallEnv("/bin-dir", "local", false)
	for key, want := range map[string]string{"GOBIN": "/bin-dir", "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod"} {
		if got := last(fallback, key); got != want {
			t.Errorf("fallback %s = %q, want %q", key, got, want)
		}
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

	_, err := installGo(t.Context(), t.TempDir(), "govulncheck",
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
	noUserToolchain(t)

	_, err := installGo(t.Context(), t.TempDir(), "govulncheck",
		goInstallable["govulncheck"], govulncheckVersion)
	if err == nil {
		t.Fatal("both attempts failing must be an error")
	}
	if !strings.Contains(err.Error(), "golang.org/x/vuln/cmd/govulncheck@v"+govulncheckVersion+" with "+govulncheckToolchain) {
		t.Errorf("the error should name what it was installing and with which Go: %v", err)
	}
}

// TestInstallGoToolRecordsWhatEndedUpOnPath is the node/python equivalent for the Go path: an
// empty version asks for the pinned one, and the binary that lands is the file the attestation is
// about. Recording a digest of anything else would attest something nobody runs. The record names
// the Go that built it, so the next install can tell this build from one made before the pin.
func TestInstallGoToolRecordsWhatEndedUpOnPath(t *testing.T) {
	noUserToolchain(t)
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
	if got.Toolchain != govulncheckToolchain {
		t.Errorf("toolchain = %q, want the pin %q", got.Toolchain, govulncheckToolchain)
	}
	if rec := loadManifest(destDir)["govulncheck"]; rec.Toolchain != govulncheckToolchain || rec.Version != govulncheckVersion {
		t.Errorf("record = %+v, want version %s built with %s", rec, govulncheckVersion, govulncheckToolchain)
	}
	if v, ok := Current(destDir, "govulncheck", ""); !ok || v != govulncheckVersion {
		t.Errorf("Current = %q, %v; a build just made at the pins is current", v, ok)
	}
}

// A Go-built tool is current when its version is the one asked for and the Go that built it is at
// least the pin. A record with no toolchain was built by whatever Go was on PATH before the pin
// existed, so an upgrade rebuilds it; one the user built with a newer Go is left alone.
func TestAGoBuiltToolIsCurrentOnlyAtOrAboveTheToolchainPin(t *testing.T) {
	for _, tc := range []struct {
		name, toolchain string
		want            bool
	}{
		{"no toolchain recorded", "", false},
		{"a toolchain below the pin", "go1.26.10", false},
		{"the pin", govulncheckToolchain, true},
		{"a toolchain above the pin", "go1.99.0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			destDir := filepath.Join(t.TempDir(), "bin")
			if err := os.MkdirAll(destDir, 0o750); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(destDir, "govulncheck")
			if err := os.WriteFile(path, []byte("binary"), 0o700); err != nil { // #nosec G306 -- stands in for a tool
				t.Fatal(err)
			}
			sum, err := fileSHA256(path)
			if err != nil {
				t.Fatal(err)
			}
			recordInstall(destDir, "govulncheck", installRecord{
				Version: govulncheckVersion, BinarySHA256: sum, Verified: LevelPinned, Toolchain: tc.toolchain,
			})
			if _, ok := Current(destDir, "govulncheck", ""); ok != tc.want {
				t.Errorf("Current = %v, want %v", ok, tc.want)
			}
		})
	}
}

// A tool not built with Go has no toolchain to be held to.
func TestToolchainCurrentIgnoresAToolNotBuiltWithGo(t *testing.T) {
	if !toolchainCurrent("semgrep", "") {
		t.Error("a tool not built with Go was held to a toolchain")
	}
}

// Doctor flags a build below the pin and nothing else: not the pin, not a newer Go, not a binary
// whose build Go could not be read, and not a tool that is not built with Go.
func TestGoToolchainBehind(t *testing.T) {
	for _, tc := range []struct {
		name, tool, buildGo string
		want                bool
	}{
		{"below the pin", "govulncheck", "go1.26.10", true},
		{"the pin", "govulncheck", govulncheckToolchain, false},
		{"above the pin", "govulncheck", "go1.99.0", false},
		{"not read", "govulncheck", "", false},
		{"not a Go version", "govulncheck", "devel", false},
		{"not built with Go", "trivy", "go1.20.0", false},
	} {
		if got := GoToolchainBehind(tc.tool, tc.buildGo); got != tc.want {
			t.Errorf("%s: GoToolchainBehind(%s, %q) = %v, want %v", tc.name, tc.tool, tc.buildGo, got, tc.want)
		}
	}
}

// Every Go-built tool has a toolchain to be built with, or it would be built with whatever Go is
// on PATH and never held to anything.
func TestEveryGoToolHasAToolchainPin(t *testing.T) {
	for name := range goInstallable {
		if !strings.HasPrefix(GoToolchain(name), "go") {
			t.Errorf("%s has no toolchain pin: %q", name, GoToolchain(name))
		}
	}
}

// The test binary is a Go binary, so it reads as the Go that built it; a file that is not one
// reads as nothing rather than as a version.
func TestReadBuildGo(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ReadBuildGo(self), strings.Fields(runtime.Version())[0]; got != want {
		t.Errorf("ReadBuildGo(test binary) = %q, want %q", got, want)
	}
	script := filepath.Join(t.TempDir(), "govulncheck")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- stands in for a tool
		t.Fatal(err)
	}
	if got := ReadBuildGo(script); got != "" {
		t.Errorf("ReadBuildGo(script) = %q, want nothing", got)
	}
}

// Detect reads the build Go of a tool Draugr builds with Go, and of no other.
func TestDetectReadsTheBuildGoOfAGoBuiltTool(t *testing.T) {
	orig := readBuildGo
	t.Cleanup(func() { readBuildGo = orig })
	readBuildGo = func(string) string { return "go1.26.10" }
	run := func(context.Context, []string, ...string) ([]byte, error) { return []byte("1.0.0"), nil }
	lookPath := func(name string) (string, error) { return "/bin/" + name, nil }

	if st := Detect(t.Context(), Catalog()["govulncheck"], lookPath, run); st.BuildGo != "go1.26.10" {
		t.Errorf("govulncheck BuildGo = %q, want go1.26.10", st.BuildGo)
	}
	if st := Detect(t.Context(), Catalog()["trivy"], lookPath, run); st.BuildGo != "" {
		t.Errorf("trivy BuildGo = %q, want nothing", st.BuildGo)
	}
}

// An explicit version overrides the pin, the path `tools install govulncheck --version` takes.
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
