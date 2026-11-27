package tools

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/draugrhome"
)

// clearToolWriteVars unsets every variable toolWrites names for the length of the test, restoring
// them after, since PointToolWritesUnderDraugrHome sets them on the process.
func clearToolWriteVars(t *testing.T) {
	t.Helper()
	for _, writes := range toolWrites {
		for _, w := range writes {
			t.Setenv(w.Var, "")
			_ = os.Unsetenv(w.Var)
		}
	}
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	// Go's defaults come from GOPATH and its settings file as well, so neither may leak in.
	t.Setenv("GOPATH", "")
	t.Setenv("GOENV", "off")
}

// readOnlyDir is a directory nothing can be written into, or a skip where the test runs as root,
// who can write to it anyway.
func readOnlyDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes through permission bits")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil { // #nosec G302 -- the test's own temp dir, made read-only on purpose
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) }) // #nosec G302 -- writable again so the test can remove it
	return dir
}

// With DRAUGR_HOME set, each tool's own variable points under its data/, so nothing a scan's tools
// write lands in the home directory. A variable somebody already set is theirs and stays.
func TestDraugrHomeMovesWhatEachToolWrites(t *testing.T) {
	clearToolWriteVars(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv(draugrhome.EnvVar, root)
	mine := filepath.Join(t.TempDir(), "my-trivy-cache")
	t.Setenv("TRIVY_CACHE_DIR", mine)

	if err := PointToolWritesUnderDraugrHome(); err != nil {
		t.Fatal(err)
	}
	for tool, writes := range toolWrites {
		for _, w := range writes {
			got := os.Getenv(w.Var)
			if w.Stays {
				if got != "" {
					t.Errorf("%s: %s = %q, but Go's caches stay where Go puts them", tool, w.Var, got)
				}
				continue
			}
			if w.Var == "TRIVY_CACHE_DIR" {
				if got != mine {
					t.Errorf("TRIVY_CACHE_DIR was set before Draugr ran and is now %q", got)
				}
				continue
			}
			if want := filepath.Join(root, "data", w.Under); got != want {
				t.Errorf("%s: %s = %q, want %q", tool, w.Var, got, want)
			}
			if !UnderDraugrHome(got) {
				t.Errorf("%s: %q is not recognized as under DRAUGR_HOME", tool, got)
			}
		}
	}
	if UnderDraugrHome(mine) {
		t.Errorf("%q is outside DRAUGR_HOME", mine)
	}
	if UnderDraugrHome(filepath.Join(root, "data-other")) {
		t.Error("a sibling whose name starts with data is not under data/")
	}
}

// Without DRAUGR_HOME each tool keeps its own default, which other installs of it share.
func TestWithoutDraugrHomeNoToolIsMoved(t *testing.T) {
	clearToolWriteVars(t)
	t.Setenv(draugrhome.EnvVar, "")
	if err := PointToolWritesUnderDraugrHome(); err != nil {
		t.Fatal(err)
	}
	for _, writes := range toolWrites {
		for _, w := range writes {
			if v, ok := os.LookupEnv(w.Var); ok {
				t.Errorf("%s set to %q with no DRAUGR_HOME", w.Var, v)
			}
		}
	}
	if UnderDraugrHome("/anything") {
		t.Error("nothing is under DRAUGR_HOME when it is unset")
	}
}

// A home directory that cannot be written stops a tool whose default is under it, and the place
// named is that default, with DRAUGR_HOME as what to change.
func TestUnwritableForNamesTheToolsDefault(t *testing.T) {
	clearToolWriteVars(t)
	t.Setenv(draugrhome.EnvVar, "")
	home := readOnlyDir(t)
	t.Setenv("HOME", home)

	got := UnwritableFor("trivy")
	if len(got) != 1 {
		t.Fatalf("UnwritableFor(trivy) = %+v, want its one cache under the read-only home", got)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(cache, "trivy"); got[0].Path != want || got[0].Var != "TRIVY_CACHE_DIR" || got[0].Named {
		t.Errorf("UnwritableFor(trivy) = %+v, want %s from the default", got[0], want)
	}
	// Semgrep writes its settings and its log in one directory, and both are named.
	semgrep := UnwritableFor("semgrep")
	if len(semgrep) != 2 || semgrep[0].Path != filepath.Join(home, ".semgrep", "settings.yml") ||
		semgrep[1].Path != filepath.Join(home, ".semgrep", "semgrep.log") {
		t.Errorf("UnwritableFor(semgrep) = %+v, want its settings file and its log", semgrep)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go on PATH to say where its caches are")
	}
	// Both of Go's caches are under the home at their defaults, and one run names both, so whoever
	// moves the first does not learn of the second only on the next run.
	gosec := UnwritableFor("gosec")
	if len(gosec) != 2 {
		t.Fatalf("UnwritableFor(gosec) = %+v, want Go's module and build caches", gosec)
	}
	mod, build := gosec[0], gosec[1]
	if want := filepath.Join(home, "go", "pkg", "mod"); mod.Path != want || mod.Var != "GOMODCACHE" || !mod.Stays || mod.Named {
		t.Errorf("first = %+v, want Go's default module cache %s", mod, want)
	}
	if build.Var != "GOCACHE" || !strings.HasPrefix(build.Path, home) || !build.Stays || build.Named {
		t.Errorf("second = %+v, want Go's default build cache under %s", build, home)
	}
}

// gosec and govulncheck load the code through the Go toolchain, so a module or build cache that
// cannot be written stops them. Go's caches are checked where Go puts them, and DRAUGR_HOME does
// not move them.
func TestUnwritableForChecksGosCaches(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go on PATH to say where its caches are")
	}
	clearToolWriteVars(t)
	t.Setenv(draugrhome.EnvVar, t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "mod"))
	ro := filepath.Join(readOnlyDir(t), "go-build")
	t.Setenv("GOCACHE", ro)
	if err := PointToolWritesUnderDraugrHome(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("GOCACHE"); got != ro {
		t.Fatalf("DRAUGR_HOME moved GOCACHE to %q", got)
	}
	for _, tool := range []string{"gosec", "govulncheck"} {
		u := UnwritableFor(tool)
		if len(u) != 1 || u[0].Path != ro || u[0].Var != "GOCACHE" || !u[0].Stays || !u[0].Named {
			t.Errorf("UnwritableFor(%s) = %+v, want only %s, named by GOCACHE", tool, u, ro)
		}
	}
	t.Setenv("GOCACHE", "off")
	if u := UnwritableFor("gosec"); u != nil {
		t.Errorf("with GOCACHE=off Go writes no build cache, and gosec was reported as %+v", u)
	}
}

// With no go on PATH there is nothing to say where Go's caches are, and nothing is reported. The
// tool's own check then fails for want of Go.
func TestUnwritableForWithoutGoReportsNothing(t *testing.T) {
	clearToolWriteVars(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", readOnlyDir(t))
	if u := UnwritableFor("gosec"); u != nil {
		t.Errorf("UnwritableFor(gosec) with no go = %+v", u)
	}
}

// The tool's own variable, set by somebody, is the place checked and the thing to change.
func TestUnwritableForFollowsAVariableSomebodySet(t *testing.T) {
	clearToolWriteVars(t)
	t.Setenv(draugrhome.EnvVar, "")
	t.Setenv("HOME", t.TempDir())
	ro := filepath.Join(readOnlyDir(t), "cache")
	t.Setenv("TRIVY_CACHE_DIR", ro)

	got := UnwritableFor("trivy")
	if len(got) != 1 || got[0].Path != ro || !got[0].Named {
		t.Fatalf("UnwritableFor(trivy) = %+v, want %s, named by its variable", got, ro)
	}
	t.Setenv("TRIVY_CACHE_DIR", filepath.Join(t.TempDir(), "a", "b"))
	if got := UnwritableFor("trivy"); got != nil {
		t.Errorf("a place that does not exist yet under a writable directory is writable: %+v", got)
	}
}

// Under DRAUGR_HOME the place is Draugr's choice, so DRAUGR_HOME is what to change.
func TestUnwritableUnderDraugrHomeIsNotNamed(t *testing.T) {
	clearToolWriteVars(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(draugrhome.EnvVar, readOnlyDir(t))
	if err := PointToolWritesUnderDraugrHome(); err != nil {
		t.Fatal(err)
	}
	got := UnwritableFor("syft")
	if len(got) != 1 || got[0].Named {
		t.Fatalf("UnwritableFor(syft) = %+v, want unwritable and not named", got)
	}
}

// An existing file is judged by opening it for writing, without changing it.
func TestCanWriteAnExistingFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through permission bits")
	}
	f := filepath.Join(t.TempDir(), "settings.yml")
	if err := os.WriteFile(f, []byte("keep: me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !canWrite(f) {
		t.Error("a writable file was reported unwritable")
	}
	if err := os.Chmod(f, 0o400); err != nil {
		t.Fatal(err)
	}
	if canWrite(f) {
		t.Error("a read-only file was reported writable")
	}
	if b, _ := os.ReadFile(f); string(b) != "keep: me\n" { // #nosec G304 -- the file this test wrote
		t.Errorf("the check changed the file: %q", b)
	}
	entries, err := os.ReadDir(filepath.Dir(f))
	if err != nil || len(entries) != 1 {
		t.Errorf("the check left something behind: %v %v", entries, err)
	}
}

// Every default is under the home directory, which is what makes a read-only home the case to
// check, and each names a place rather than nothing.
func TestEveryDefaultIsUnderHome(t *testing.T) {
	clearToolWriteVars(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	for tool, writes := range toolWrites {
		for _, w := range writes {
			got := w.Default()
			if rel, err := filepath.Rel(home, got); err != nil || rel == "." || strings.HasPrefix(rel, "..") {
				t.Errorf("%s: %s defaults to %q, not under %s", tool, w.Var, got, home)
			}
		}
	}
}

// WritePath answers with the variable's value where it is set, the tool's default where it is not,
// and nothing for a variable the tool does not read.
func TestWritePathFollowsTheVariableThenTheDefault(t *testing.T) {
	clearToolWriteVars(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	if got, want := WritePath("cosign", "TUF_ROOT"), filepath.Join(home, ".sigstore", "root"); got != want {
		t.Errorf("default = %q, want %q", got, want)
	}
	set := filepath.Join(t.TempDir(), "tuf")
	t.Setenv("TUF_ROOT", set)
	if got := WritePath("cosign", "TUF_ROOT"); got != set {
		t.Errorf("set = %q, want %q", got, set)
	}
	if got := WritePath("cosign", "TRIVY_CACHE_DIR"); got != "" {
		t.Errorf("a variable cosign does not read = %q", got)
	}
	if got := WritePath("no-such-tool", "TUF_ROOT"); got != "" {
		t.Errorf("an unknown tool = %q", got)
	}
}
