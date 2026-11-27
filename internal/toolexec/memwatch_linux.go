package toolexec

import (
	"bytes"
	"context"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// canWatch says a memory bound is enforced here: Linux lists every process's group and resident
// memory under /proc.
const canWatch = true

// killedFirst is the oom_score_adj each tool is given. The kernel adds it, in thousandths of the
// memory it is choosing within, to a process's score, so at 500 a tool outscores Draugr unless
// Draugr holds half that memory more than the tool does. An unprivileged process may raise the
// value of a process it owns and not lower it, which is why the tools are raised rather than
// Draugr lowered.
const killedFirst = "500"

// preferKilled makes the tool the kernel's first choice over Draugr when memory runs out, by raising
// its oom_score_adj. The tool sets it before it reads anything; a process it started in the moment
// before keeps the value it inherited. Where the write fails, the tool runs as it would have and the
// reason is logged at debug.
func preferKilled(ctx context.Context, pid int) {
	file := filepath.Join("/proc", strconv.Itoa(pid), "oom_score_adj")
	if err := os.WriteFile(file, []byte(killedFirst), 0); err != nil {
		slog.DebugContext(ctx, "could not make the tool the kernel's first choice to kill", "pid", pid, "error", err)
	}
}

// watchInterval is how often the bounded tools' memory is read. A tool can grow past its bound by
// what it allocates in this long before it is stopped.
var watchInterval = 250 * time.Millisecond

// procRoot is where the process table is read.
var procRoot = "/proc"

// watched is one bounded tool: its bound, and whether the watch stopped it.
type watched struct {
	bound uint64
	over  atomic.Bool
}

// watcher holds every bounded tool running, by its process group. One sweep of /proc serves them
// all, so a run with many jobs at once reads the process table once per interval, not once per job.
var watcher struct {
	mu      sync.Mutex
	groups  map[int]*watched
	running bool
}

// watch holds the process group pgid to bound bytes of resident memory, summed across its
// processes, until the returned function is called, which says whether the group was stopped for
// passing it. The group is the tool and every process it started that did not leave it (inOwnGroup).
func watch(pgid int, bound uint64) (stop func() bool) {
	w := &watched{bound: bound}
	watcher.mu.Lock()
	if watcher.groups == nil {
		watcher.groups = map[int]*watched{}
	}
	watcher.groups[pgid] = w
	if !watcher.running {
		watcher.running = true
		go sweep()
	}
	watcher.mu.Unlock()
	return func() bool {
		watcher.mu.Lock()
		delete(watcher.groups, pgid)
		watcher.mu.Unlock()
		return w.over.Load()
	}
}

// sweep reads the bounded groups' memory every watchInterval and stops each group past its bound,
// until no group is left to watch.
func sweep() {
	tick := time.NewTicker(watchInterval)
	defer tick.Stop()
	for range tick.C {
		watcher.mu.Lock()
		if len(watcher.groups) == 0 {
			watcher.running = false
			watcher.mu.Unlock()
			return
		}
		groups := maps.Clone(watcher.groups)
		watcher.mu.Unlock()
		used := groupMemory(procRoot, groups)
		for pgid, w := range groups {
			if used[pgid] > w.bound && !w.over.Swap(true) {
				// The negative pid names the group, as a canceled run's kill does.
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			}
		}
	}
}

// groupMemory sums the resident memory of every process under root whose process group is one of
// groups, in bytes. A process that exits while it is read, or whose stat cannot be parsed, counts
// for nothing. Memory two processes share, such as a library both map, counts once for each, so the
// sum can exceed what the group takes from the machine.
func groupMemory(root string, groups map[int]*watched) map[int]uint64 {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	page := uint64(os.Getpagesize()) // #nosec G115 -- a page size is positive
	used := map[int]uint64{}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(root, e.Name(), "stat")) // #nosec G304 -- a path under the process table
		if err != nil {
			continue
		}
		pgrp, rss, ok := parseStat(stat)
		if !ok {
			continue
		}
		if _, bounded := groups[pgrp]; bounded {
			used[pgrp] += rss * page
		}
	}
	return used
}

// parseStat reads a process's group and resident pages from its /proc/<pid>/stat line, documented
// in proc_pid_stat(5). The command name, the second field, is in parentheses and may hold spaces and
// parentheses itself, so the fields are counted from the last closing one: after it come the state,
// the parent's pid, the process group (field 5) and, twentieth after the group, rss (field 24).
func parseStat(stat []byte) (pgrp int, rss uint64, ok bool) {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, 0, false
	}
	fields := bytes.Fields(stat[end+1:])
	if len(fields) < 22 {
		return 0, 0, false
	}
	pgrp, err := strconv.Atoi(string(fields[2]))
	if err != nil {
		return 0, 0, false
	}
	rss, err = strconv.ParseUint(string(fields[21]), 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return pgrp, rss, true
}
