package scanners

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// concurrency counts how many fake Trivy runs of each subcommand are in flight, and the most at once.
type concurrency struct {
	mu        sync.Mutex
	now, most map[string]int
}

func (c *concurrency) enter(sub string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.now == nil {
		c.now, c.most = map[string]int{}, map[string]int{}
	}
	c.now[sub]++
	c.most[sub] = max(c.most[sub], c.now[sub])
}

func (c *concurrency) leave(sub string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now[sub]--
}

// The image jobs of one run take turns at Trivy's on-disk cache rather than racing for its lock,
// which `trivy image` holds for the whole pull: four image scans started together never overlap,
// while filesystem scans, whose cache is in memory, still run side by side. The time spent waiting
// is the tool's, where the report shows it.
func TestTrivyImageScansOfOneRunTakeTurnsAtTheCache(t *testing.T) {
	prior := execArgv
	t.Cleanup(func() { execArgv = prior })
	var seen concurrency
	execArgv = func(_ context.Context, argv []string) ([]byte, error) {
		seen.enter(argv[1])
		defer seen.leave(argv[1])
		time.Sleep(30 * time.Millisecond)
		return []byte(`{"Results":[]}`), nil
	}
	waits := &plugin.WaitRecorder{}
	ctx := plugin.WithWaitRecorder(context.Background(), waits)
	run := trivyScanRun()
	var wg sync.WaitGroup
	for _, sub := range []string{"image", "image", "image", "image", "fs", "fs", "fs"} {
		wg.Go(func() {
			if _, err := run(ctx, []string{"trivy", sub, "--quiet", "target"}); err != nil {
				t.Errorf("trivy %s: %v", sub, err)
			}
		})
	}
	wg.Wait()
	if seen.most["image"] != 1 {
		t.Errorf("%d image scans ran at once; they share one cache lock and must take turns", seen.most["image"])
	}
	if seen.most["fs"] < 2 {
		t.Errorf("filesystem scans ran at most %d at once; their cache is in memory and needs no turn", seen.most["fs"])
	}
	if waits.Totals()["trivy"] <= 0 {
		t.Errorf("waits recorded %v; the image scans' turns should show as trivy's wait", waits.Totals())
	}
}

// A run stopped while an image job waits for its turn returns the run's own error, and the job's
// scan never starts.
func TestAnImageScanWaitingForItsTurnStopsWithTheRun(t *testing.T) {
	prior := execArgv
	t.Cleanup(func() { execArgv = prior })
	var started atomic.Int32
	execArgv = func(context.Context, []string) ([]byte, error) {
		started.Add(1)
		return nil, nil
	}
	release, err := holdTrivyImageCache(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = trivyScanRun()(ctx, []string{"trivy", "image", "registry.example/app:1"})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the run's context.Canceled", err)
	}
	if started.Load() != 0 {
		t.Error("the scan started without its turn at the cache")
	}
}

// Between retries for a holder outside this process, the turn is given back, so the run's other
// image jobs are not held up by a lock none of them has.
func TestARetriedImageScanGivesItsTurnBackBetweenAttempts(t *testing.T) {
	prior, priorBase := execArgv, lockBackoffBase
	t.Cleanup(func() { execArgv, lockBackoffBase = prior, priorBase })
	lockBackoffBase = 200 * time.Millisecond
	attempts := 0
	freeDuringBackoff := make(chan bool, 1)
	execArgv = func(context.Context, []string) ([]byte, error) {
		attempts++
		if attempts == 1 {
			// The attempt holds the turn, so another job cannot take it now.
			select {
			case trivyImageCache <- struct{}{}:
				<-trivyImageCache
				t.Error("the attempt runs without holding the turn")
			default:
			}
			// Once this attempt has failed and the retry is waiting, another job can.
			go func() {
				time.Sleep(50 * time.Millisecond)
				select {
				case trivyImageCache <- struct{}{}:
					<-trivyImageCache
					freeDuringBackoff <- true
				default:
					freeDuringBackoff <- false
				}
			}()
			return nil, errors.New("unable to initialize fs cache: cache may be in use by another process: timeout")
		}
		return []byte(`{"Results":[]}`), nil
	}
	if _, err := trivyScanRun()(context.Background(), []string{"trivy", "image", "registry.example/app:1"}); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Errorf("ran %d attempts, want 2", attempts)
	}
	if !<-freeDuringBackoff {
		t.Error("the turn stayed taken while the retry waited for a holder outside this process")
	}
	select {
	case trivyImageCache <- struct{}{}:
		<-trivyImageCache
	default:
		t.Error("the turn was not given back after the scan")
	}
}
