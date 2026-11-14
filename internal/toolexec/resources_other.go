//go:build !linux && !darwin

package toolexec

import "os"

// totalMemory reports no memory on a platform Draugr does not read it on, and the bound then
// follows the core count alone.
func totalMemory() uint64 { return 0 }

// peakChildMemory reports nothing on a platform without getrusage(2), and report.json then omits
// the figure.
func peakChildMemory() (uint64, bool) { return 0, false }

// selfPeakMemory reports nothing on a platform without getrusage(2), and report.json then omits
// the figure.
func selfPeakMemory() (uint64, bool) { return 0, false }

// processPeak reports nothing on a platform whose wait does not report resident memory.
func processPeak(*os.ProcessState) (uint64, bool) { return 0, false }
