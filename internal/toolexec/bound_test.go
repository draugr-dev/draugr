package toolexec

import (
	"context"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const gib = 1 << 30

// The bound is half the cores or one per 4 GiB of memory, whichever is fewer, never below one and
// never above the cores; with the memory unknown, the cores alone decide.
func TestBoundTakesTheFewerOfHalfTheCoresAndOnePerFourGiB(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cores  int
		memory uint64
		want   int
	}{
		{"memory decides on a many-core machine", 32, 62 * gib, 15},
		{"cores decide where memory is plentiful", 32, 256 * gib, 16},
		{"a laptop", 8, 16 * gib, 4},
		{"little memory per core", 8, 8 * gib, 2},
		{"less memory than one unit", 4, 2 * gib, 1},
		{"one core", 1, 64 * gib, 1},
		{"memory unreadable", 16, 0, 8},
		{"memory unreadable on two cores", 2, 0, 1},
		{"no cores reported", 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := bound(tc.cores, tc.memory); got != tc.want {
				t.Errorf("bound(%d, %d GiB) = %d, want %d", tc.cores, tc.memory/gib, got, tc.want)
			}
		})
	}
}

// What a run adds is decided against the values the tool would see: the caller's choices stand,
// the caller's other GOFLAGS stay, and a later entry for a key is the one read.
func TestBoundEnvKeepsWhatTheCallerChose(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want []string
	}{
		{"nothing set", nil, []string{"GOMAXPROCS=4", "GOFLAGS=-p=4"}},
		{"other flags kept", []string{"GOFLAGS=-mod=mod -tags=aaa,bbb"}, []string{"GOMAXPROCS=4", "GOFLAGS=-mod=mod -tags=aaa,bbb -p=4"}},
		{"the caller's -p kept", []string{"GOFLAGS=-mod=mod -p=2"}, []string{"GOMAXPROCS=4"}},
		{"the caller's --p kept", []string{"GOFLAGS=--p=2"}, []string{"GOMAXPROCS=4"}},
		{"a bare -p counts", []string{"GOFLAGS=-p"}, []string{"GOMAXPROCS=4"}},
		{"-pgo is not -p", []string{"GOFLAGS=-pgo=auto -pkgdir=/x"}, []string{"GOMAXPROCS=4", "GOFLAGS=-pgo=auto -pkgdir=/x -p=4"}},
		{"a value is not a flag", []string{"GOFLAGS=p=2"}, []string{"GOMAXPROCS=4", "GOFLAGS=p=2 -p=4"}},
		{"the caller's GOMAXPROCS kept", []string{"GOMAXPROCS=3"}, []string{"GOFLAGS=-p=4"}},
		{"an empty GOMAXPROCS is unset", []string{"GOMAXPROCS="}, []string{"GOMAXPROCS=4", "GOFLAGS=-p=4"}},
		{"the last entry is read", []string{"GOFLAGS=-p=2", "GOFLAGS=-mod=mod"}, []string{"GOMAXPROCS=4", "GOFLAGS=-mod=mod -p=4"}},
		{"both chosen", []string{"GOMAXPROCS=3", "GOFLAGS=-p=3"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := boundEnv(tc.env, 4); !slices.Equal(got, tc.want) {
				t.Errorf("boundEnv(%q) = %q, want %q", tc.env, got, tc.want)
			}
		})
	}
}

// envOf runs `env` through one entry point and returns the value each of keys had in the child.
func envOf(t *testing.T, run func(argv []string) ([]byte, error), keys ...string) map[string]string {
	t.Helper()
	out, err := run([]string{"env"})
	if err != nil {
		t.Fatalf("run env: %v", err)
	}
	got := map[string]string{}
	for line := range strings.Lines(string(out)) {
		k, v, _ := strings.Cut(strings.TrimRight(line, "\n"), "=")
		if slices.Contains(keys, k) {
			got[k] = v
		}
	}
	return got
}

// Every entry point gives the tool the bound, including the ones a caller passes no environment
// to, and keeps the caller's other GOFLAGS.
func TestEveryEntryPointRunsTheToolUnderTheBound(t *testing.T) {
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-tags=aaa")
	ctx := context.Background()
	n := strconv.Itoa(Parallelism())
	for name, run := range map[string]func([]string) ([]byte, error){
		"Run":                func(argv []string) ([]byte, error) { return Run(ctx, "", argv) },
		"RunCombined":        func(argv []string) ([]byte, error) { return RunCombined(ctx, "", argv) },
		"RunWithEnv":         func(argv []string) ([]byte, error) { return RunWithEnv(ctx, "", argv, nil) },
		"RunCombinedWithEnv": func(argv []string) ([]byte, error) { return RunCombinedWithEnv(ctx, "", argv, nil) },
		"RunWithStderr": func(argv []string) ([]byte, error) {
			out, _, err := RunWithStderr(ctx, "", argv, nil)
			return out, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := envOf(t, run, "GOMAXPROCS", "GOFLAGS")
			if got["GOMAXPROCS"] != n {
				t.Errorf("GOMAXPROCS = %q, want %q", got["GOMAXPROCS"], n)
			}
			if want := "-tags=aaa -p=" + n; got["GOFLAGS"] != want {
				t.Errorf("GOFLAGS = %q, want %q", got["GOFLAGS"], want)
			}
		})
	}
}

// A GOMAXPROCS and a -p the caller set are the ones the tool runs with.
func TestTheCallersBoundWins(t *testing.T) {
	t.Setenv("GOMAXPROCS", "3")
	t.Setenv("GOFLAGS", "-mod=mod -p=2")
	got := envOf(t, func(argv []string) ([]byte, error) { return Run(context.Background(), "", argv) }, "GOMAXPROCS", "GOFLAGS")
	if got["GOMAXPROCS"] != "3" || got["GOFLAGS"] != "-mod=mod -p=2" {
		t.Errorf("the tool ran with GOMAXPROCS=%q GOFLAGS=%q, want the caller's 3 and -mod=mod -p=2", got["GOMAXPROCS"], got["GOFLAGS"])
	}
}

// A scanner's own environment layers over the caller's, and the bound is added to what it sets
// rather than replaced by it.
func TestAScannersEnvironmentKeepsTheBound(t *testing.T) {
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-tags=aaa")
	n := strconv.Itoa(Parallelism())
	got := envOf(t, func(argv []string) ([]byte, error) {
		return RunWithEnv(context.Background(), "", argv, []string{"GOFLAGS=-tags=bbb", "DRAUGR_TOOL_VAR=x"})
	}, "GOMAXPROCS", "GOFLAGS", "DRAUGR_TOOL_VAR")
	if got["GOFLAGS"] != "-tags=bbb -p="+n || got["GOMAXPROCS"] != n || got["DRAUGR_TOOL_VAR"] != "x" {
		t.Errorf("the tool ran with %v, want the scanner's GOFLAGS with -p=%s, GOMAXPROCS=%s and its own variable", got, n, n)
	}
	got = envOf(t, func(argv []string) ([]byte, error) {
		return RunWithEnv(context.Background(), "", argv, []string{"GOMAXPROCS=5"})
	}, "GOMAXPROCS")
	if got["GOMAXPROCS"] != "5" {
		t.Errorf("GOMAXPROCS = %q, want the scanner's 5", got["GOMAXPROCS"])
	}
}

// The go command reads GOFLAGS on every subcommand, including the ones that build nothing, so a
// -p it refused would break every Go tool Draugr runs rather than bound it.
func TestTheGoCommandAcceptsTheBound(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go on PATH")
	}
	t.Setenv("GOFLAGS", "")
	for _, argv := range [][]string{{"go", "env", "GOVERSION"}, {"go", "version"}, {"go", "list", "-f", "{{.Name}}", "."}} {
		if out, err := RunCombined(context.Background(), "", argv); err != nil {
			t.Errorf("%s under the bound: %v\n%s", strings.Join(argv, " "), err, out)
		}
	}
}

// The bound on this machine is the formula over what the operating system reports.
func TestParallelismReadsThisMachine(t *testing.T) {
	if got, want := Parallelism(), bound(runtime.NumCPU(), totalMemory()); got != want {
		t.Errorf("Parallelism() = %d, want %d", got, want)
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if totalMemory() == 0 {
			t.Error("totalMemory() = 0 on a platform that reports it")
		}
	}
}

// Once a tool has run and been waited for, its resident memory is readable.
func TestPeakMemoryReadsTheProcessesWaitedFor(t *testing.T) {
	if _, err := Run(context.Background(), "", []string{"env"}); err != nil {
		t.Fatalf("run env: %v", err)
	}
	peak, ok := PeakMemory()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		if ok {
			t.Errorf("PeakMemory() = %d, true on a platform that does not report it", peak)
		}
		return
	}
	// Any process holds more than a page; a figure below that is a unit read wrongly.
	if !ok || peak < 64<<10 {
		t.Errorf("PeakMemory() = %d, %v, want at least 64 KiB", peak, ok)
	}
}
