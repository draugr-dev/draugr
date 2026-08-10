package report

import (
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// "Fix first" describes a shortlist. Over the whole set it stops being a recommendation and
// becomes a label, and the reader loses what the default view was telling them.
func TestFixFirstHeading(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		s            summary
		shown, total int
		want         string
	}{
		{"a shortlist says so", summary{}, 10, 437, "Fix first (top 10 of 437, by priority):"},
		{"the whole set is not a shortlist", summary{}, 437, 437, "All 437 findings, by priority:"},
		{"one finding is not a list", summary{}, 1, 1, "The finding (by priority):"},
		{"filtered and capped", summary{minPriority: "p2"}, 10, 50,
			"Fix first (top 10 of 50, by priority, P2 and above):"},
		{"filtered, hiding some", summary{minPriority: "p1", hidden: 12}, 3, 3,
			"All 3 findings, by priority, P1 and above; 12 lower-priority finding(s) hidden:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := fixFirstHeading(tc.s, tc.shown, tc.total); got != tc.want {
				t.Errorf("heading = %q,\n    want %q", got, tc.want)
			}
		})
	}
}

// One component repeats the same value on every row and answers a question nobody has. The
// column earns its width only when it tells findings apart.
func TestComponentColumnOnlyWhenItDistinguishes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		fs   []finding
		want bool
	}{
		{"no components", []finding{{}, {}}, false},
		{"one component", []finding{{component: "web"}, {component: "web"}}, false},
		{"two components", []finding{{component: "web"}, {component: "api"}}, true},
		{"one named, one not", []finding{{component: "web"}, {}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := manyComponents(tc.fs); got != tc.want {
				t.Errorf("manyComponents = %v, want %v", got, tc.want)
			}
		})
	}
}

// The engine has recorded this since caching was added and nothing showed it, which left
// `--cache-dir` unverifiable at a terminal: the run is faster, and whether the cache did it is a
// question the output did not answer.
func TestRunLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		stats engine.Stats
		want  string
	}{
		{
			name:  "a run with no jobs describes nothing",
			stats: engine.Stats{Duration: time.Second},
		},
		{
			// A duration of zero means the run never finished, not that it was instant.
			name:  "an unfinished run describes nothing",
			stats: engine.Stats{Jobs: 4},
		},
		{
			name:  "jobs and wall-clock",
			stats: engine.Stats{Jobs: 4, Duration: 2500 * time.Millisecond},
			want:  "Ran 4 jobs in 2.5s.",
		},
		{
			name:  "one job reads as one",
			stats: engine.Stats{Jobs: 1, Duration: 247 * time.Millisecond},
			want:  "Ran 1 job in 247ms.",
		},
		{
			name:  "cache hits are the answer to whether the cache worked",
			stats: engine.Stats{Jobs: 11, CacheHits: 4, Duration: 3 * time.Second},
			want:  "Ran 11 jobs in 3s — 4 from cache.",
		},
		{
			// Two components sharing a repository plan two jobs and one scan answers both. Without
			// a name for it, a reader counting jobs against scans finds a discrepancy and no cause.
			name:  "a shared scan is a different saving from a cache hit",
			stats: engine.Stats{Jobs: 16, Deduped: 5, Duration: 4951 * time.Millisecond},
			want:  "Ran 16 jobs in 4.951s — 5 shared with an identical job.",
		},
		{
			name:  "both savings",
			stats: engine.Stats{Jobs: 11, CacheHits: 4, Deduped: 1, Duration: 34500 * time.Millisecond},
			want:  "Ran 11 jobs in 34.5s — 4 from cache, 1 shared with an identical job.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := runLine(tc.stats); got != tc.want {
				t.Errorf("runLine = %q, want %q", got, tc.want)
			}
		})
	}
}
