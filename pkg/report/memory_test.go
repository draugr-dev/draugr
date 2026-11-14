package report

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

func TestMemorySize(t *testing.T) {
	for b, want := range map[uint64]string{
		512:            "512 B",
		61341696:       "58 MiB",
		3 << 29:        "1.5 GiB",
		40 << 30:       "40 GiB",
		1 << 40:        "1.0 TiB",
		261439488 * 10: "2.4 GiB",
	} {
		if got := memorySize(b); got != want {
			t.Errorf("memorySize(%d) = %q, want %q", b, got, want)
		}
	}
}

// memoryStats is a run of two scanners over two repositories: semgrep's larger job is the one its
// row names, and Draugr's own figure leads.
func memoryStats() engine.Stats {
	return engine.Stats{
		PeakOwnMemory: 61341696,
		MemoryLimit:   40 << 30,
		JobMemory: []engine.JobMemory{
			{Scanner: "gitleaks", Target: "a", PeakBytes: 62914560},
			{Scanner: "semgrep", Target: "a", PeakBytes: 104857600},
			{Scanner: "semgrep", Target: "b", PeakBytes: 261439488},
		},
	}
}

// The row names the scanner whose largest process used the most, from the larger of its jobs, then
// Draugr's own peak and the memory the run could use, as the run row names the slowest scanner.
func TestMemoryEvidenceNamesTheLargestScanner(t *testing.T) {
	want := "semgrep used the most, 249 MiB at its peak · Draugr itself 58 MiB · 40 GiB available"
	if got := memoryEvidence(memoryStats()); got != want {
		t.Errorf("memoryEvidence = %q\nwant            %q", got, want)
	}
}

// A platform that reports no figure prints no row, rather than a row of zeros or a limit alone.
func TestMemoryEvidenceIsSilentWithoutAFigure(t *testing.T) {
	if got := memoryEvidence(engine.Stats{MemoryLimit: 40 << 30}); got != "" {
		t.Errorf("memoryEvidence = %q, want nothing", got)
	}
	st := memoryStats()
	st.MemoryLimit, st.JobMemory = 0, nil
	if got := memoryEvidence(st); got != "Draugr itself 58 MiB" {
		t.Errorf("memoryEvidence with Draugr's figure alone = %q", got)
	}
}
