package toolexec

import (
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// A tool sizes its own parallelism to the machine. A Go tool runs GOMAXPROCS threads, every core
// by default, and a tool that loads Go packages, govulncheck or gosec, starts `go` commands whose
// build parallelism, -p, defaults to the same number. Each compile process of such a build holds
// a package's type information, so on a large module the memory those processes take together
// grows with the core count rather than with the module. A machine with many cores and less memory
// per core runs out of memory, and -j does not prevent it: it bounds how many jobs run at once,
// and each job's tool still uses every core.
//
// So every tool run is given one bound, n, as GOMAXPROCS and as -p in GOFLAGS, unless the caller
// already chose either. A run of -j jobs then has at most -j × n threads and compile processes.
// A tool that runs several `go` commands at once divides n among them (Divide), since each
// command would otherwise build with all of it.

// memoryPerUnit is the memory each unit of the bound is allowed: one compile process of a large
// module's build together with the share of the tool that started it.
const memoryPerUnit = 4 << 30

// parallelism is the bound for this process, computed once from the machine. The cores are this
// process's GOMAXPROCS, which the Go runtime lowers to a container's CPU limit, so a tool in a
// container limited to two CPUs is not given half of the host's.
var parallelism = sync.OnceValue(func() int { return bound(runtime.GOMAXPROCS(0), totalMemory()) })

// Parallelism is the bound every tool run is given as GOMAXPROCS and as -p in GOFLAGS, where the
// caller set neither, computed once per process from the machine's cores and memory.
func Parallelism() int { return parallelism() }

// bound is the parallelism a tool is given on a machine with cores CPUs and memory bytes of
// memory: half the cores, or one per memoryPerUnit of memory where that is fewer, at least one and
// at most cores. memory is zero where the operating system did not report it, and the core term
// alone then decides.
func bound(cores int, memory uint64) int {
	n := cores / 2
	if memory > 0 {
		n = min(n, int(min(memory/memoryPerUnit, math.MaxInt32))) // #nosec G115 -- clamped to an int32
	}
	return max(1, min(n, cores))
}

// environ is the environment a tool runs with: the caller's, then extra, then the bound wherever
// neither of those chose it.
func environ(extra []string) []string {
	env := append(os.Environ(), extra...)
	return append(env, boundEnv(env, parallelism())...)
}

// boundEnv is what a run whose environment is env adds for the bound n: GOMAXPROCS where env sets
// none, and GOFLAGS with -p=n after its existing flags where they hold no -p. The values read are
// the ones the tool would see, the last entry for each key.
func boundEnv(env []string, n int) []string {
	var add []string
	if lookup(env, "GOMAXPROCS") == "" {
		add = append(add, "GOMAXPROCS="+strconv.Itoa(n))
	}
	return append(add, buildBound(env, n)...)
}

// buildBound is the GOFLAGS entry that gives a run whose environment is env the build parallelism
// p: its existing flags, then -p=p. Nothing where those flags already hold a -p.
func buildBound(env []string, p int) []string {
	goflags := lookup(env, "GOFLAGS")
	if setsBuildParallelism(goflags) {
		return nil
	}
	return []string{"GOFLAGS=" + strings.TrimSpace(goflags+" -p="+strconv.Itoa(p))}
}

// Divide shares the bound among the `go` commands one tool runs at once, for a tool that runs up to
// commands of them. It returns how many the tool should run at once, commands or the bound where
// that is fewer and at least one, and the environment that tool runs with: GOFLAGS with -p at the
// bound divided by that many, rounded down and at least one, after the caller's other flags. Each
// command then builds with at most that -p, so together they run at most the bound's compile
// processes rather than the bound's for each.
//
// The environment is for the tool's run to pass as its own, which the bound is layered over:
// GOMAXPROCS stays the whole bound, because it sizes the tool's own threads and not its builds. A
// caller whose GOFLAGS sets -p keeps it, and the environment is then empty: that caller chose each
// command's parallelism, and the count returned still bounds how many commands run.
func Divide(commands int) (concurrent int, env []string) {
	return divide(os.Environ(), parallelism(), commands)
}

// divide is Divide for a run whose environment is env under the bound n.
func divide(env []string, n, commands int) (int, []string) {
	c := max(1, min(commands, n))
	return c, buildBound(env, max(1, n/c))
}

// lookup is the value of key in env, from its last entry, or empty where env has none.
func lookup(env []string, key string) string {
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], key+"="); ok {
			return v
		}
	}
	return ""
}

// setsBuildParallelism reports whether a GOFLAGS value sets -p, as `-p=8` or `--p=8`. GOFLAGS
// takes each flag with its value after an equals sign, so a `-p` field alone is counted too, and
// `-pgo=auto` or `-pkgdir=…` is not -p.
func setsBuildParallelism(goflags string) bool {
	for _, f := range strings.Fields(goflags) {
		if !strings.HasPrefix(f, "-") {
			continue
		}
		if name, _, _ := strings.Cut(strings.TrimLeft(f, "-"), "="); name == "p" {
			return true
		}
	}
	return false
}

// PeakMemory is the largest resident memory, in bytes, of any single process this one has run and
// waited for, including the processes those started and waited for, and false where the
// operating system does not report it. It is the largest one process reached, not a sum, and it
// covers the life of this process.
func PeakMemory() (uint64, bool) {
	return peakChildMemory()
}
