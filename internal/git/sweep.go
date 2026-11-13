package git

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The temporary directories a run makes. Each name carries the run's process id, tempPrefix's
// "draugr-repo-4242-…", so a later run can tell a directory whose owner is still working from one
// whose owner is gone.
const (
	repoPrefix     = "draugr-repo-"
	worktreePrefix = "draugr-worktree-"
	treePrefix     = "draugr-tree-"
)

// tempPrefix is the os.MkdirTemp pattern for a directory of kind, naming this process.
func tempPrefix(kind string) string {
	return kind + strconv.Itoa(os.Getpid()) + "-"
}

// SweepStale removes, from dir, the checkouts that runs no longer alive left behind.
//
// A run removes its checkouts as it goes and at the end, but a run killed outright, for memory or
// by a second interrupt, never reaches either. Its checkouts are read-only, so a plain `rm -rf`
// fails on them too, and without this they would stay until the machine is rebooted, which for a
// tmpfs is memory held for nothing.
//
// Only directories whose name says which process made it are touched, and only when that process
// has ended. A directory named without a process id belongs to an older release, which might still
// be running, so it is left alone. Best effort throughout: nothing here is a reason to fail a scan.
func SweepStale(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, ok := ownerOf(e.Name())
		if !ok || pid == self || processAlive(pid) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		thaw(path)
		_ = os.RemoveAll(path)
	}
}

// ownerOf reads the process id from a name tempPrefix made, and reports whether there was one.
func ownerOf(name string) (int, bool) {
	for _, kind := range []string{repoPrefix, worktreePrefix, treePrefix} {
		rest, ok := strings.CutPrefix(name, kind)
		if !ok {
			continue
		}
		digits, _, ok := strings.Cut(rest, "-")
		if !ok {
			return 0, false
		}
		pid, err := strconv.Atoi(digits)
		if err != nil || pid <= 0 {
			return 0, false
		}
		return pid, true
	}
	return 0, false
}
