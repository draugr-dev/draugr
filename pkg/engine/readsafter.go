package engine

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// readsAfter returns, for each planned job, the positions in the plan of the jobs it waits for:
// every job on the same target whose scanner its own scanner names in ScannerInfo.ReadsAfter, or on
// any target where it sets ScannerInfo.ReadsAfterRun.
//
// A target is the same at the grain outcomeKey uses, a repository by source and revision whatever
// paths a job reads, because the state being ordered (a tool's cache filled from the repository's
// manifests) does not depend on which of its directories a job was narrowed to.
//
// Declarations that form a cycle among the planned scanners are an error, and then nothing waits:
// two jobs each waiting for the other would hold the run forever, which is worse than the
// unordered run this falls back to.
func readsAfter(reg *Registry, planned []PlannedJob) ([][]int, error) {
	byScannerAndTarget := map[string][]int{}
	byScanner := map[string][]int{}
	declared := map[string][]string{}
	runWide := map[string]bool{}
	for i, pj := range planned {
		key := pj.Job.Scanner + "\x00" + outcomeKey(pj.Job.Target)
		byScannerAndTarget[key] = append(byScannerAndTarget[key], i)
		byScanner[pj.Job.Scanner] = append(byScanner[pj.Job.Scanner], i)
		if sc, ok := reg.Scanner(pj.Job.Scanner); ok {
			declared[pj.Job.Scanner] = sc.Info().ReadsAfter
			runWide[pj.Job.Scanner] = sc.Info().ReadsAfterRun
		}
	}
	if cycle := readsAfterCycle(declared); cycle != nil {
		return nil, fmt.Errorf("scanners %s read after each other in a cycle, so their jobs ran unordered",
			strings.Join(cycle, " → "))
	}
	out := make([][]int, len(planned))
	for i, pj := range planned {
		target := outcomeKey(pj.Job.Target)
		for _, name := range declared[pj.Job.Scanner] {
			if runWide[pj.Job.Scanner] {
				out[i] = append(out[i], byScanner[name]...)
				continue
			}
			out[i] = append(out[i], byScannerAndTarget[name+"\x00"+target]...)
		}
	}
	return out, nil
}

// readsAfterCycle returns a cycle in the ReadsAfter declarations, as the scanners along it with the
// first repeated at the end, or nil when there is none. Only names with an entry in declared are
// followed: a scanner that is not there cannot hold anybody up.
//
// Visited in name order, so the cycle reported is the same on every run.
func readsAfterCycle(declared map[string][]string) []string {
	const (
		visiting = 1
		done     = 2
	)
	state := map[string]int{}
	var path []string
	var visit func(name string) []string
	visit = func(name string) []string {
		switch state[name] {
		case visiting:
			return append(slices.Clone(path[slices.Index(path, name):]), name)
		case done:
			return nil
		}
		state[name] = visiting
		path = append(path, name)
		for _, next := range declared[name] {
			if _, ok := declared[next]; !ok {
				continue
			}
			if cycle := visit(next); cycle != nil {
				return cycle
			}
		}
		path = path[:len(path)-1]
		state[name] = done
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(declared)) {
		if cycle := visit(name); cycle != nil {
			return cycle
		}
	}
	return nil
}

// CheckReadsAfter reports a registered scanner whose ScannerInfo.ReadsAfter names a scanner the
// registry does not hold, or declarations across the registry that form a cycle. Both are a
// programming error in whoever declared them, so this is for a test over the real registry rather
// than for a run, which tolerates the first (nothing of an unknown scanner is ever planned) and
// reports the second.
func (r *Registry) CheckReadsAfter() error {
	declared := map[string][]string{}
	var unknown []string
	for _, sc := range r.Scanners() {
		info := sc.Info()
		declared[info.Name] = info.ReadsAfter
		for _, name := range info.ReadsAfter {
			if _, ok := r.scanners[name]; !ok {
				unknown = append(unknown, fmt.Sprintf("%s reads after %q, which is not a registered scanner", info.Name, name))
			}
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%s", strings.Join(unknown, "; "))
	}
	if cycle := readsAfterCycle(declared); cycle != nil {
		return fmt.Errorf("scanners read after each other in a cycle: %s", strings.Join(cycle, " → "))
	}
	return nil
}

// waitToRead blocks until every job at the positions in deps has finished, however it finished,
// or ctx is done. Time spent blocked is added to waits against scanner; a job whose predecessors
// had all finished by the time it looked records nothing.
//
// Called before the job takes a concurrency slot, which is what keeps `-j 1` from deadlocking: a
// job holding the only slot while it waits for one that needs it would wait forever.
func waitToRead(ctx context.Context, waits *plugin.WaitRecorder, scanner string, deps []int, finished []chan struct{}) {
	began := time.Now()
	blocked := false
	defer func() {
		if blocked {
			waits.Add(scanner, time.Since(began))
		}
	}()
	for _, j := range deps {
		select {
		case <-finished[j]:
			continue
		default:
		}
		blocked = true
		select {
		case <-finished[j]:
		case <-ctx.Done():
			// The job goes on to find the run canceled, the same way one that never waited does.
			return
		}
	}
}
