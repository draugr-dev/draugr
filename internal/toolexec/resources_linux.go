package toolexec

import (
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
)

// totalMemory is the memory this process may use in bytes: the machine's, from sysinfo(2), or the
// cgroup's limit where that is lower, or zero where neither is known. A container or a systemd
// scope with a memory limit runs on a host whose sysinfo reports all of the host's memory, and a
// bound sized to the host would let the tools exceed the limit the process is held to.
func totalMemory() uint64 {
	var host uint64
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err == nil {
		// Converted although Totalram is a uint64 here: it is a uint32 on 32-bit platforms.
		host = uint64(si.Totalram) * uint64(si.Unit)
	}
	return lowerOf(host, cgroupMemoryLimit("/proc/self/cgroup", "/sys/fs/cgroup"))
}

// lowerOf is the lower of two memory figures, where zero means unknown rather than none.
func lowerOf(a, b uint64) uint64 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	}
	return min(a, b)
}

// cgroupMemoryLimit is the lowest memory.max on the path from this process's cgroup v2 group to
// the root, read from the membership file self and the hierarchy mounted at root, or zero where
// none is set or the process is not in a cgroup v2 hierarchy. A limit on a parent holds the child
// too, so each level is read rather than the process's own group alone.
func cgroupMemoryLimit(self, root string) uint64 {
	data, err := os.ReadFile(self) // #nosec G304 -- a fixed procfs path, or a test's fixture
	if err != nil {
		return 0
	}
	var group string
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			group = path.Clean("/" + rest)
		}
	}
	if group == "" {
		return 0
	}
	var limit uint64
	for dir := group; ; dir = path.Dir(dir) {
		limit = lowerOf(limit, memoryMax(path.Join(root, dir, "memory.max")))
		if dir == "/" {
			return limit
		}
	}
}

// memoryMax is the limit a memory.max file states in bytes, or zero for `max`, a missing file or
// anything unreadable.
func memoryMax(file string) uint64 {
	data, err := os.ReadFile(file) // #nosec G304 -- a path under the cgroup hierarchy
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// selfPeakMemory reads this process's own largest resident set from getrusage(2), which Linux
// reports in kilobytes.
func selfPeakMemory() (uint64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	return kilobytes(ru.Maxrss)
}

// processPeak reads the largest resident set of an exited process, and of the processes it waited
// for, from what wait4(2) reported for it, in kilobytes on Linux.
func processPeak(state *os.ProcessState) (uint64, bool) {
	if state == nil {
		return 0, false
	}
	ru, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0, false
	}
	return kilobytes(ru.Maxrss)
}

// kilobytes is a maxrss in kilobytes as bytes, and false where it is not positive.
func kilobytes(maxrss int64) (uint64, bool) {
	if maxrss <= 0 {
		return 0, false
	}
	return uint64(maxrss) * 1024, true // #nosec G115 -- positive, checked above
}

// peakChildMemory reads the largest resident set of the waited-for children from getrusage(2),
// which Linux reports in kilobytes.
func peakChildMemory() (uint64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &ru); err != nil {
		return 0, false
	}
	return kilobytes(ru.Maxrss)
}
