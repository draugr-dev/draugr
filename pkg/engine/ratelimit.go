package engine

import (
	"context"
	"sync"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// rateGate spaces one scanner's calls out to the rate it declared.
//
// A gate rather than a token bucket: buckets allow a burst, and a burst is what trips a vendor's
// throttle. Four requests in the first second of a minute satisfies "4 per minute" only if their
// window happens to start where ours did, and it never does.
//
// Reserves rather than sleeps-then-checks. Each caller takes the next slot and releases the lock
// immediately, so callers are served in arrival order and none can be starved by a later one.
type rateGate struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// wait blocks until this caller's turn, or the context ends.
func (g *rateGate) wait(ctx context.Context, now func() time.Time) error {
	g.mu.Lock()
	t := now()
	if g.next.Before(t) {
		g.next = t
	}
	at := g.next
	g.next = at.Add(g.interval)
	g.mu.Unlock()

	delay := at.Sub(t)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		// The reservation is not returned. Handing it back would let a cancelled run's slot be
		// reused instantly, which is a burst by another name — and a cancelled scan has no
		// remaining work to hurry.
		return ctx.Err()
	}
}

// rateGates holds one gate per scanner, created on first use.
type rateGates struct {
	mu    sync.Mutex
	gates map[string]*rateGate
	now   func() time.Time
}

func newRateGates() *rateGates {
	return &rateGates{gates: map[string]*rateGate{}, now: time.Now}
}

// wait blocks until the scanner behind this job may be called again.
//
// Scanners that do not implement plugin.RateLimited, or declare a zero rate, return immediately —
// which is nearly all of them, so the common path costs one interface assertion.
func (r *rateGates) wait(ctx context.Context, s plugin.Scanner, name string, cfg plugin.Config) error {
	limited, ok := s.(plugin.RateLimited)
	if !ok {
		return nil
	}
	interval := limited.RateLimit(cfg).Interval()
	if interval <= 0 {
		return nil
	}

	r.mu.Lock()
	g, seen := r.gates[name]
	if !seen {
		g = &rateGate{interval: interval}
		r.gates[name] = g
	}
	r.mu.Unlock()

	return g.wait(ctx, r.now)
}
