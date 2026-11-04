package toolexec

import "syscall"

// totalMemory is the machine's memory in bytes, from sysinfo(2), or zero where the call fails.
func totalMemory() uint64 {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0
	}
	// Converted although Totalram is a uint64 here: it is a uint32 on 32-bit platforms.
	return uint64(si.Totalram) * uint64(si.Unit)
}

// peakChildMemory reads the largest resident set of the waited-for children from getrusage(2),
// which Linux reports in kilobytes.
func peakChildMemory() (uint64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &ru); err != nil || ru.Maxrss <= 0 {
		return 0, false
	}
	return uint64(ru.Maxrss) * 1024, true // #nosec G115 -- positive, checked above
}
