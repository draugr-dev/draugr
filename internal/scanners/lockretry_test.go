package scanners

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// captureWarnings redirects the default logger for the duration of a test. The retry reports
// itself through slog, which is the only place a caller can see that a scan waited.
//
// captureAt collects log output at a level, restoring the previous logger afterwards.
func captureAt(t *testing.T, level slog.Level) func() string {
	t.Helper()
	var mu sync.Mutex
	buf := &lockedBuffer{mu: &mu}
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() { slog.SetDefault(prior) })
	return buf.String
}

// captureWarnings holds the CLI's own default level rather than a permissive one, so a test fails
// if something a user must see is demoted. Somewhere in the logs is not the same as on screen.
func captureWarnings(t *testing.T) func() string { return captureAt(t, slog.LevelInfo) }

// captureDebug collects what is deliberately below the default level.
func captureDebug(t *testing.T) func() string { return captureAt(t, slog.LevelDebug) }

// lockedBuffer is a bytes.Buffer safe to write from the retry goroutine and read from the test.
type lockedBuffer struct {
	mu  *sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fastBackoff shrinks the retry delay for a test. The delays themselves are not what these tests
// are about, and waiting them out would cost the suite half a minute to prove arithmetic.
func fastBackoff(t *testing.T) {
	t.Helper()
	prior := lockBackoffBase
	lockBackoffBase = time.Millisecond
	t.Cleanup(func() { lockBackoffBase = prior })
}

// errLocked is the failure Trivy reports when another process holds its cache.
var errLocked = errors.New("exit status 1: FATAL run error: image scan error: scan error: " +
	"unable to initialize a scan service: unable to initialize cache: unable to initialize fs " +
	"cache: cache may be in use by another process: timeout")

func TestRetryLockedCache(t *testing.T) {
	fastBackoff(t)

	tests := []struct {
		name     string
		errs     []error // one per attempt; nil means success
		wantCall int
		wantErr  error
	}{
		{
			name:     "a scan that works is run once",
			errs:     []error{nil},
			wantCall: 1,
		},
		{
			// The whole point: the holder finishes and the lock frees, so the work still gets done.
			name:     "a contended cache is retried until it frees",
			errs:     []error{errLocked, errLocked, nil},
			wantCall: 3,
		},
		{
			// A cache genuinely stuck must still fail, and with the tool's own message — a
			// retried error that arrives renamed sends the reader after the wrong thing.
			name:     "a cache that never frees fails with the tool's error",
			errs:     []error{errLocked, errLocked, errLocked, errLocked},
			wantCall: lockRetries + 1,
			wantErr:  errLocked,
		},
		{
			// Anything retrying cannot fix has to fail on the first attempt. Backing off for a
			// minute before reporting a missing binary is worse than reporting it at once.
			name:     "an unrelated failure is not retried",
			errs:     []error{errors.New("trivy: no such image")},
			wantCall: 1,
			wantErr:  errors.New("trivy: no such image"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			_, err := retryLockedCache(t.Context(), "trivy", func() ([]byte, error) {
				e := tc.errs[calls]
				calls++
				return nil, e
			})
			if calls != tc.wantCall {
				t.Errorf("ran %d times, want %d", calls, tc.wantCall)
			}
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("want success, got %v", err)
			case tc.wantErr != nil && err == nil:
				t.Fatalf("want %v, got success", tc.wantErr)
			case tc.wantErr != nil && err.Error() != tc.wantErr.Error():
				t.Errorf("error = %q, want %q", err, tc.wantErr)
			}
		})
	}
}

// A canceled run was told to stop; it did not fail to scan. Reporting the lock would send the
// reader after a cache problem they do not have.
func TestRetryLockedCacheStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	done := make(chan error, 1)
	go func() {
		_, err := retryLockedCache(ctx, "trivy", func() ([]byte, error) {
			calls++
			if calls == 1 {
				cancel()
			}
			return nil, errLocked
		})
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a canceled run should not sit out its backoff")
	}
	if calls != 1 {
		t.Errorf("ran %d times after cancellation, want 1", calls)
	}
}

// The marker has to match what Trivy actually prints, including through the wrapping every caller
// adds. Matching a message the tool does not produce is a retry that never fires.
func TestIsLockedCacheMatchesWhatTheToolPrints(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("run trivy: %w", errLocked)
	if !isLockedCache(wrapped) {
		t.Error("the wrapped tool error should be recognized")
	}
	if !strings.Contains(errLocked.Error(), lockedCacheMarker) {
		t.Errorf("the marker %q is not in the message Trivy prints", lockedCacheMarker)
	}
	for _, other := range []error{
		nil,
		errors.New("exit status 1: FATAL failed to download vulnerability DB"),
		errors.New("exec: \"trivy\": executable file not found in $PATH"),
	} {
		if isLockedCache(other) {
			t.Errorf("%v should not be treated as a locked cache", other)
		}
	}
}

// A run that retried has to say so. A scan taking three times as long for a reason nobody can see
// is the same failure in a quieter form — but the reason is the total, not a line per wait: the
// waits happen in concurrent jobs and overlap, so a reader adding up individual messages would
// overstate the cost. The total is recorded for the run to report once, beside its duration.
func TestRetryLockedCacheRecordsWhatItWaited(t *testing.T) {
	fastBackoff(t)
	recorder := &plugin.WaitRecorder{}
	ctx := plugin.WithWaitRecorder(t.Context(), recorder)
	calls := 0
	if _, err := retryLockedCache(ctx, "trivy", func() ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errLocked
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := recorder.Totals()["trivy"]; got <= 0 {
		t.Errorf("the wait was not recorded, so the run has no reason to give: %v", got)
	}
}

// The per-attempt line stays, at debug, for whoever is diagnosing contention.
func TestRetryLockedCacheExplainsItselfAtDebug(t *testing.T) {
	fastBackoff(t)
	logs := captureDebug(t)
	calls := 0
	if _, err := retryLockedCache(t.Context(), "trivy", func() ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errLocked
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	got := logs()
	if !strings.Contains(got, "waiting for the scanner cache") {
		t.Errorf("the wait was not explained at debug:\n%s", got)
	}

	// And deliberately not at the default level. One line per attempt is noise a reader cannot
	// act on, and it multiplies: three retries per job means a scan with many jobs fills the
	// screen before it reports anything. The reason a slow scan owes its reader is the total,
	// which the run gives beside its duration. Asserted so restoring it here is a decision
	// rather than an oversight.
	atDefault := captureWarnings(t)
	calls = 0
	if _, err := retryLockedCache(t.Context(), "trivy", func() ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errLocked
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(atDefault(), "waiting for the scanner cache") {
		t.Error("the per-attempt wait is back at the default level, where it is a wall of " +
			"identical lines nobody can act on")
	}
	// The holder is one of this scan's own jobs. Calling it another scan sends a reader looking
	// for a second Draugr process, and there is never one to find.
	if strings.Contains(got, "another scan") {
		t.Errorf("the wait must not blame a scan the reader did not start:\n%s", got)
	}
}

// Registering the retry is not the same as reaching it. Every Trivy-backed scanner shares the
// cache, so each one has to be wrapped — and a constructor that forgets is invisible until a
// contended run in somebody's CI.
func TestEveryTrivyScannerRetriesALockedCache(t *testing.T) {
	fastBackoff(t)
	for _, tc := range []struct {
		name string
		make func() plugin.Scanner
	}{
		{"trivy-fs", NewTrivyFS},
		{"trivy-config", NewTrivyConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Substituted before the constructor runs, so what is exercised is the run function
			// the constructor actually installed.
			calls := 0
			prior := execArgvInDir
			t.Cleanup(func() { execArgvInDir = prior })
			execArgvInDir = func(context.Context, string, []string) ([]byte, error) {
				calls++
				if calls <= 2 {
					return nil, errLocked
				}
				return nil, nil
			}

			s, ok := tc.make().(repoScanner)
			if !ok {
				t.Fatalf("%s is not a repoScanner", tc.name)
			}
			if _, err := s.run(t.Context(), t.TempDir(), []string{"trivy"}); err != nil {
				t.Fatal(err)
			}
			if calls != 3 {
				t.Errorf("ran %d times, want the contended attempts retried", calls)
			}
		})
	}
}
