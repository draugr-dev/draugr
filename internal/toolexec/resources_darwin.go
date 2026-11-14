package toolexec

import (
	"encoding/binary"
	"os"
	"syscall"
)

// totalMemory is the machine's memory in bytes, from the hw.memsize sysctl, or zero where the call
// fails.
func totalMemory() uint64 {
	v, err := syscall.Sysctl("hw.memsize")
	if err != nil || len(v) > 8 {
		return 0
	}
	// Sysctl returns the integer's bytes as a string, in the machine's order, which is little-endian
	// on every Mac Go builds for, and drops a final zero byte as though ending a C string. Padding
	// back to eight bytes restores it.
	var b [8]byte
	copy(b[:], v)
	return binary.LittleEndian.Uint64(b[:])
}

// selfPeakMemory reads this process's own largest resident set from getrusage(2), which macOS
// reports in bytes.
func selfPeakMemory() (uint64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil || ru.Maxrss <= 0 {
		return 0, false
	}
	return uint64(ru.Maxrss), true // #nosec G115 -- positive, checked above
}

// processPeak reads the largest resident set of an exited process, and of the processes it waited
// for, from what wait4(2) reported for it, in bytes on macOS.
func processPeak(state *os.ProcessState) (uint64, bool) {
	if state == nil {
		return 0, false
	}
	ru, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil || ru.Maxrss <= 0 {
		return 0, false
	}
	return uint64(ru.Maxrss), true // #nosec G115 -- positive, checked above
}

// peakChildMemory reads the largest resident set of the waited-for children from getrusage(2),
// which macOS reports in bytes.
func peakChildMemory() (uint64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &ru); err != nil || ru.Maxrss <= 0 {
		return 0, false
	}
	return uint64(ru.Maxrss), true // #nosec G115 -- positive, checked above
}
