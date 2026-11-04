//go:build !linux && !darwin

package toolexec

// totalMemory reports no memory on a platform Draugr does not read it on, and the bound then
// follows the core count alone.
func totalMemory() uint64 { return 0 }

// peakChildMemory reports nothing on a platform without getrusage(2), and report.json then omits
// the figure.
func peakChildMemory() (uint64, bool) { return 0, false }
