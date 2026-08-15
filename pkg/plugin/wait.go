package plugin

import (
	"context"
	"maps"
	"sync"
	"time"
)

// WaitRecorder collects time a run spent queueing rather than scanning, per tool.
//
// It exists because "this took three times as long" is a question the job count cannot answer,
// and the honest answer is a total rather than a line per wait: waits happen inside concurrent
// jobs, so they overlap, and a reader adding up individual messages would overstate the cost even
// if they were willing to.
//
// Safe for concurrent use — every recorded wait comes from a different job.
type WaitRecorder struct {
	mu     sync.Mutex
	byTool map[string]time.Duration
}

// Totals returns the recorded wait per tool. The caller owns the copy.
func (r *WaitRecorder) Totals() map[string]time.Duration {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.byTool) == 0 {
		return nil
	}
	return maps.Clone(r.byTool)
}

// add records a wait against a tool.
func (r *WaitRecorder) add(tool string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byTool == nil {
		r.byTool = map[string]time.Duration{}
	}
	r.byTool[tool] += d
}

type waitRecorderKey struct{}

// WithWaitRecorder returns a context that collects waits recorded during a scan.
//
// Carried on the context rather than handed to scanners directly, because a scanner should not
// have to be given a way to report this in order to be written — one that never calls RecordWait
// simply records nothing, and one nested three helpers deep can still reach it.
func WithWaitRecorder(ctx context.Context, r *WaitRecorder) context.Context {
	return context.WithValue(ctx, waitRecorderKey{}, r)
}

// RecordWait attributes time spent waiting to a tool, if anything is collecting.
//
// A no-op when nothing is — a scanner called outside a run, or from a test, must not have to set
// one up, and losing the measurement is not a reason to change behaviour.
func RecordWait(ctx context.Context, tool string, d time.Duration) {
	if r, ok := ctx.Value(waitRecorderKey{}).(*WaitRecorder); ok {
		r.add(tool, d)
	}
}
