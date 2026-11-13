package toolexec

import (
	"context"
	"runtime"
	"strconv"
	"testing"
)

// The default job count follows the CPUs and the memory the process may use, the fewer of one per
// CPU and one per two GiB, and never falls to zero.
func TestDefaultJobsTakesTheFewerOfTheCPUsAndOnePerTwoGiB(t *testing.T) {
	const gib = 1 << 30
	for _, tc := range []struct {
		name   string
		cores  int
		memory uint64
		want   int
	}{
		{"a pod limited to 4 CPUs and 8 GiB on a large node", 4, 8 * gib, 4},
		{"64 cores and 8 GiB", 64, 8 * gib, 4},
		{"a 4-core laptop with 7.6 GiB", 4, 7*gib + 600<<20, 3},
		{"64 cores and 512 GiB", 64, 512 * gib, 64},
		{"less memory than one job's share", 8, 1 * gib, 1},
		{"memory not reported", 6, 0, 6},
		{"no CPU reported", 0, 0, 1},
	} {
		if got := jobs(tc.cores, tc.memory); got != tc.want {
			t.Errorf("%s: jobs(%d, %d) = %d, want %d", tc.name, tc.cores, tc.memory, got, tc.want)
		}
	}
}

// A CPU limit lower than the host's lowers the default: GOMAXPROCS is what Go sets from a
// container's CPU limit, and the default reads it rather than the host's core count.
func TestDefaultJobsFollowsTheCPUsThisProcessMayUse(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Skip("needs a host with more than one CPU to set a lower limit")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	if got := DefaultJobs(); got != 1 {
		t.Errorf("DefaultJobs() = %d with GOMAXPROCS 1 on %d CPUs, want 1", got, runtime.NumCPU())
	}
}

// Each job's tools get the bound divided among the jobs running at once, and a job alone gets it
// whole.
func TestBoundIsTheJobsShare(t *testing.T) {
	n := Parallelism()
	ctx := context.Background()
	for _, tc := range []struct {
		jobs int
		want int
	}{
		{0, n},
		{1, n},
		{2, max(1, n/2)},
		{n + 1, 1},
	} {
		if got := Bound(WithJobs(ctx, tc.jobs)); got != tc.want {
			t.Errorf("Bound with %d jobs = %d, want %d of %d", tc.jobs, got, tc.want, n)
		}
	}
	if got := Bound(ctx); got != n {
		t.Errorf("Bound outside a run = %d, want the whole bound %d", got, n)
	}
}

// A tool started for one of two jobs starts with half the bound, as GOMAXPROCS and as -p.
func TestATwoJobRunStartsEachToolWithHalf(t *testing.T) {
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "")
	ctx := WithJobs(context.Background(), 2)
	half := strconv.Itoa(max(1, Parallelism()/2))
	got := envOf(t, func(argv []string) ([]byte, error) { return Run(ctx, "", argv) }, "GOMAXPROCS", "GOFLAGS")
	if got["GOMAXPROCS"] != half || got["GOFLAGS"] != "-p="+half {
		t.Errorf("GOMAXPROCS=%q GOFLAGS=%q, want %s and -p=%s", got["GOMAXPROCS"], got["GOFLAGS"], half, half)
	}
}
