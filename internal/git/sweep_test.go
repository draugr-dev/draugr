package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// deadPID returns the id of a process that has exited.
func deadPID(t *testing.T) int {
	t.Helper()
	name, args := "true", []string{}
	if runtime.GOOS == "windows" {
		name, args = "cmd", []string{"/c", "exit"}
	}
	cmd := exec.Command(name, args...) // #nosec G204 -- a fixed command chosen above, to get a pid that has exited
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot start a process to outlive: %v", err)
	}
	return cmd.Process.Pid
}

// frozenDir makes a read-only checkout named name under dir, as a killed run leaves one.
func frozenDir(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(path, "src"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "src", "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	freeze(path)
	t.Cleanup(func() { thaw(path); _ = os.RemoveAll(path) })
	return path
}

func TestSweepRemovesWhatDeadRunsLeft(t *testing.T) {
	dir := t.TempDir()
	dead := strconv.Itoa(deadPID(t))
	live := strconv.Itoa(os.Getppid())
	self := strconv.Itoa(os.Getpid())

	gone := []string{
		frozenDir(t, dir, "draugr-repo-"+dead+"-123"),
		frozenDir(t, dir, "draugr-worktree-"+dead+"-456"),
		frozenDir(t, dir, "draugr-tree-"+dead+"-789"),
	}
	kept := []string{
		frozenDir(t, dir, "draugr-repo-"+live+"-123"), // a run still working
		frozenDir(t, dir, "draugr-repo-"+self+"-123"), // this run's own
		frozenDir(t, dir, "draugr-repo-1956481920"),   // an older release, which may be running
		frozenDir(t, dir, "draugr-repo-x-1"),
		frozenDir(t, dir, "something-else-"+dead+"-1"),
	}
	if err := os.WriteFile(filepath.Join(dir, "draugr-repo-"+dead+"-file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	SweepStale(dir)

	for _, path := range gone {
		if exists(path) {
			t.Errorf("a dead run's checkout is still on disk: %s", filepath.Base(path))
		}
	}
	for _, path := range kept {
		if !exists(path) {
			t.Errorf("removed %s, which no dead run made", filepath.Base(path))
		}
	}
	if !exists(filepath.Join(dir, "draugr-repo-"+dead+"-file")) {
		t.Error("removed a file; only directories are checkouts")
	}
}

func TestSweepOfAMissingDirectoryDoesNothing(t *testing.T) {
	SweepStale(filepath.Join(t.TempDir(), "absent"))
}

func TestACheckoutIsNamedForItsRun(t *testing.T) {
	prefix := tempPrefix(repoPrefix)
	if !strings.HasPrefix(prefix, "draugr-repo-") {
		t.Fatalf("prefix %q", prefix)
	}
	pid, ok := ownerOf(prefix + "123456")
	if !ok || pid != os.Getpid() {
		t.Errorf("ownerOf(%q) = %d, %t, want this process", prefix+"123456", pid, ok)
	}
}
