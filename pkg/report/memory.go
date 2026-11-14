package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// memorySize is a count of bytes as a person reads it, in the binary units `--help` uses for the
// memory a job is given: one decimal under ten, whole numbers above.
func memorySize(b uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v, u := float64(b), 0
	for v >= 1024 && u < len(units)-1 {
		v /= 1024
		u++
	}
	if u > 0 && v < 10 {
		return fmt.Sprintf("%.1f %s", v, units[u])
	}
	return fmt.Sprintf("%.0f %s", v, units[u])
}

// scannerPeak is the largest resident memory one process of a scanner's jobs reached.
type scannerPeak struct {
	scanner string
	bytes   uint64
}

// scannerPeaks are the run's scanners by the largest process any of their jobs ran, largest first.
// Per scanner rather than per job: a scanner run once per repository has as many jobs as the
// descriptor has repositories, and the question a row answers is which tool costs the memory.
func scannerPeaks(jobs []engine.JobMemory) []scannerPeak {
	at := map[string]uint64{}
	for _, j := range jobs {
		at[j.Scanner] = max(at[j.Scanner], j.PeakBytes)
	}
	out := make([]scannerPeak, 0, len(at))
	for s, b := range at {
		out = append(out, scannerPeak{s, b})
	}
	slices.SortFunc(out, func(a, b scannerPeak) int {
		return cmp.Or(cmp.Compare(b.bytes, a.bytes), cmp.Compare(a.scanner, b.scanner))
	})
	return out
}

// memoryEvidence is the EVIDENCE block's memory row, in the shape of the run row above it: the
// scanner whose largest process used the most memory and how much at its peak, Draugr's own peak,
// and the memory the run could use. Only the largest scanner is named, as the run row names only
// the one that took the most time; report.json keeps every job's figure. Empty where the operating
// system reported nothing.
func memoryEvidence(st engine.Stats) string {
	var parts []string
	if peaks := scannerPeaks(st.JobMemory); len(peaks) > 0 {
		parts = append(parts, peaks[0].scanner+" used the most, "+memorySize(peaks[0].bytes)+" at its peak")
	}
	if st.PeakOwnMemory > 0 {
		parts = append(parts, "Draugr itself "+memorySize(st.PeakOwnMemory))
	}
	if len(parts) > 0 && st.MemoryLimit > 0 {
		parts = append(parts, memorySize(st.MemoryLimit)+" available")
	}
	return strings.Join(parts, " · ")
}
