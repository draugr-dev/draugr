package engine

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// exclusiveLocks holds one lock per resource a planned scanner declares in ScannerInfo.Exclusive,
// each a channel with room for one: a send takes the lock and a receive releases it. A channel
// rather than a sync.Mutex so a job waiting for the lock can give up when the run is canceled.
//
// Built before the run's jobs start and only read after, so it needs no lock of its own.
type exclusiveLocks map[string]chan struct{}

// newExclusiveLocks makes a lock for each resource some planned job's scanner declares.
func newExclusiveLocks(reg *Registry, planned []PlannedJob) exclusiveLocks {
	locks := exclusiveLocks{}
	for _, pj := range planned {
		sc, ok := reg.Scanner(pj.Job.Scanner)
		if !ok {
			continue
		}
		if name := sc.Info().Exclusive; name != "" && locks[name] == nil {
			locks[name] = make(chan struct{}, 1)
		}
	}
	return locks
}

// acquire takes the lock for resource on behalf of a job of scanner, blocking until the job
// holding it ends or ctx is done. It returns the function that releases the lock, and false when
// the run was canceled before the lock was free; the job then holds nothing and goes no further.
// A resource that is empty or has no lock needs none, and acquire returns at once.
//
// Time spent blocked is added to waits against scanner: it is a wait for other jobs' work, the same
// kind ScannerInfo.ReadsAfter records. A job that found the lock free records nothing.
//
// Called after waitToRead and before the job takes a concurrency slot. A job never waits for the
// jobs it reads after while holding the lock, so a job holding it waits only for a slot, which a
// job holds only while it scans; and a job waiting for the lock holds no slot, so under `-j 1` the
// job holding the lock can still take one.
func (l exclusiveLocks) acquire(ctx context.Context, waits *plugin.WaitRecorder, scanner, resource string) (func(), bool) {
	lock := l[resource]
	if lock == nil {
		return func() {}, true
	}
	release := func() { <-lock }
	select {
	case lock <- struct{}{}:
		return release, true
	default:
	}
	began := time.Now()
	defer func() { waits.Add(scanner, time.Since(began)) }()
	select {
	case lock <- struct{}{}:
		return release, true
	case <-ctx.Done():
		// The job goes no further, the same way one canceled while waiting out its rate limit does.
		return nil, false
	}
}

// CheckExclusive reports a registered scanner whose ScannerInfo.Exclusive is not one of known.
// Two scanners meant to share a resource and naming it differently would each take a lock of
// their own and run beside each other, so this is for a test over the real registry, given the
// declared resource constants, rather than for a run.
func (r *Registry) CheckExclusive(known ...string) error {
	var unknown []string
	for _, sc := range r.Scanners() {
		info := sc.Info()
		if info.Exclusive != "" && !slices.Contains(known, info.Exclusive) {
			unknown = append(unknown, fmt.Sprintf("%s is exclusive on %q, which is not a declared resource", info.Name, info.Exclusive))
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%s", strings.Join(unknown, "; "))
	}
	return nil
}
