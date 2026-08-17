package cli

import (
	"context"
	"syscall"
	"testing"
	"time"
)

// A scan holds things that have to be given back — a temporary checkout, a privileged Job in
// somebody's cluster — and every one is released by a deferred cleanup. A deferred cleanup runs
// when a function returns, not when a process is killed, so the interrupt has to become a
// cancellation rather than a termination.
//
// Not parallel: it sends a signal to this process, and signal disposition is process-wide.
func TestAnInterruptCancelsRatherThanTerminates(t *testing.T) {
	ctx, stop := onInterrupt(context.Background())
	defer stop()

	if ctx.Err() != nil {
		t.Fatal("the context should be live before any signal")
	}
	// Safe to send: onInterrupt has already registered a handler, so this is delivered to us
	// rather than to the default disposition, which would end the test binary.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal this process: %v", err)
	}

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the signal did not cancel the scan's context, so no cleanup would run")
	}
}

// stop() is deferred by Execute and runs on the ordinary path, where nothing was signaled. It has
// to release the handler and the goroutine without waiting for one.
func TestStopReleasesTheHandlerWithoutASignal(t *testing.T) {
	ctx, stop := onInterrupt(context.Background())
	done := make(chan struct{})
	go func() { stop(); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop() blocked waiting for a signal that never came")
	}
	if ctx.Err() == nil {
		t.Error("stop() should cancel the context it handed out")
	}
	// Idempotent: Execute defers it, and a test or a caller may call it too.
	stop()
}
