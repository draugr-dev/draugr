//go:build !windows

package toolexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// pidIn waits for a script to write a process id into path and returns it.
func pidIn(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) != "" { // #nosec G304 -- the test's own temporary file
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no pid written to %s", path)
	return 0
}

// gone reports whether pid has ended within a couple of seconds. A killed process can linger as a
// zombie until whoever adopted it reaps it, which kill(pid, 0) still finds.
func gone(pid int) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		if b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")); err == nil &&
			strings.Contains(string(b), ") Z ") {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// Canceling a tool ends the processes it started too, and the run returns at once rather than
// waiting on them.
func TestCancelingAToolEndsTheProcessesItStarted(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, "", []string{"sh", "-c", "sleep 300 & echo $! > " + pidFile + "; wait"})
		done <- err
	}()
	child := pidIn(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })

	canceled := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(pipeWait + 5*time.Second):
		t.Fatal("a canceled run is still waiting on its tool")
	}
	if waited := time.Since(canceled); waited > 3*time.Second {
		t.Errorf("a canceled run took %s to return", waited)
	}
	if !gone(child) {
		t.Errorf("the tool's child %d is still running after the run was canceled", child)
	}
}

// A tool that succeeds while a process it detached keeps its output open is a success, after a
// bounded wait, rather than a run that waits for as long as the helper lives.
func TestAToolThatExitsLeavingAHelperOnItsOutputSucceeds(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "helper.pid")
	started := time.Now()
	out, err := Run(context.Background(), "", []string{"sh", "-c",
		"setsid sh -c 'echo $$ > " + pidFile + "; exec sleep 300' & echo done"})
	helper := pidIn(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(helper, syscall.SIGKILL) })
	if err != nil {
		t.Fatalf("a tool that exited 0 failed: %v", err)
	}
	if strings.TrimSpace(string(out)) != "done" {
		t.Errorf("output = %q, want what the tool wrote", out)
	}
	if waited := time.Since(started); waited > pipeWait+5*time.Second {
		t.Errorf("the run waited %s on a helper holding its output", waited)
	}
}
