package scanners

import (
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"strings"
	"time"
)

// Trivy keeps its analysis results in a BoltDB under the cache directory, and takes an exclusive
// write lock to store them. Every Trivy-backed scanner shares that cache, and Draugr plans one job
// per image and per repository and runs them concurrently — so on a run where analysis is slow,
// two processes can want the lock for longer than Trivy is willing to wait, and the one that loses
// fails its whole scan.
//
// Waiting is the right response: the condition clears on its own the moment the holder finishes,
// which is what makes it worth retrying rather than reporting. What is not acceptable is retrying
// silently — a scan that took three times as long for a reason nobody can see is the same problem
// in a quieter form, so each wait is logged.
//
// Deliberately narrow. It matches the one message Trivy prints for this and nothing else: a
// scanner that fails for a reason retrying cannot fix must still fail on the first attempt, or a
// broken cache costs a minute of backoff before saying so.
const lockedCacheMarker = "cache may be in use by another process"

// lockRetries is how many times a scan is retried after the first attempt.
//
// Three, because the wait is bounded by how long one scan holds the lock, and a contended cache
// with more waiters than that is a scheduling problem retrying will not solve — at which point
// failing is the more useful answer.
const lockRetries = 3

// lockBackoffBase is the first wait; each retry doubles it. A var so a test can exercise the
// retry without sitting out the real delays, which would put half a minute into every run of the
// suite to prove arithmetic.
var lockBackoffBase = 2 * time.Second

// retryLockedCache runs fn, retrying while the tool reports that its cache is held elsewhere.
//
// The backoff is jittered because the contending processes are Draugr's own, started together and
// therefore failing together: a fixed delay would have them all wake at the same moment and
// contend again, turning one collision into a synchronised series of them.
func retryLockedCache(ctx context.Context, tool string, fn func() ([]byte, error)) ([]byte, error) {
	wait := lockBackoffBase
	for attempt := 0; ; attempt++ {
		out, err := fn()
		if err == nil || attempt == lockRetries || !isLockedCache(err) {
			return out, err
		}
		delay := wait + jitter(wait/2)
		slog.WarnContext(ctx, "scanner cache is held by another scan, waiting",
			"tool", tool, "attempt", attempt+1, "of", lockRetries, "wait", delay.Round(time.Millisecond).String())
		select {
		case <-ctx.Done():
			// The caller's error, not the tool's: a cancelled run did not fail to scan, it was
			// told to stop, and reporting the lock would send the reader after the wrong thing.
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		wait *= 2
	}
}

// isLockedCache reports whether an error is the tool saying another process holds its cache.
func isLockedCache(err error) bool {
	return err != nil && strings.Contains(err.Error(), lockedCacheMarker)
}

// retryingRun wraps a tooladapter run function with the cache-lock retry.
func retryingRun(tool string, run func(context.Context, []string) ([]byte, error)) func(context.Context, []string) ([]byte, error) {
	return func(ctx context.Context, argv []string) ([]byte, error) {
		return retryLockedCache(ctx, tool, func() ([]byte, error) { return run(ctx, argv) })
	}
}

// retryingRunInDir wraps a repoScanner run function with the cache-lock retry.
func retryingRunInDir(tool string, run func(context.Context, string, []string) ([]byte, error)) func(context.Context, string, []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		return retryLockedCache(ctx, tool, func() ([]byte, error) { return run(ctx, dir, argv) })
	}
}

// jitter returns a random duration in [0, d).
//
// From crypto/rand rather than math/rand. Nothing here needs unpredictability — this is a backoff,
// not a token — but a scanner reaching for a weak generator is a finding in every SAST tool worth
// running, including the two this project gates itself with. Suppressing it would cost a reader
// more attention than the source costs to pick correctly.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)))
	if err != nil {
		// The system entropy source failing is not a reason to abandon a retry; a fixed delay is
		// worse only in that contending scans wake together, which is what the retry limit bounds.
		return d / 2
	}
	return time.Duration(n.Int64())
}
