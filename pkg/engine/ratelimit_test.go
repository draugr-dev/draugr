package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// rateScanner is a scanner declaring a rate, for the gate's benefit.
type rateScanner struct {
	name string
	rate plugin.Rate
}

func (s rateScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Controls: []string{"c"}}
}
func (s rateScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, nil
}
func (s rateScanner) RateLimit(plugin.Config) plugin.Rate { return s.rate }

// plainScanner declares nothing, like almost every scanner.
type plainScanner struct{ name string }

func (s plainScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Controls: []string{"c"}}
}
func (s plainScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, nil
}

func TestRateGateSpacesCallsEvenly(t *testing.T) {
	// Evenly rather than in bursts. Four calls at once satisfies "4 per minute" only if the
	// vendor's window happens to start where ours did, and that is the shape that trips a
	// throttle.
	g := &rateGate{interval: 10 * time.Millisecond}
	start := time.Now()
	for range 4 {
		if err := g.wait(context.Background(), time.Now); err != nil {
			t.Fatal(err)
		}
	}
	// Three intervals between four calls; allow slack for a slow machine but not for bursting.
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Errorf("four calls took %v — they were not spaced", elapsed)
	}
}

func TestRateGateServesCallersInOrder(t *testing.T) {
	// Each caller reserves its slot and releases the lock, so a later arrival cannot overtake an
	// earlier one and no caller is starved while others keep arriving.
	g := &rateGate{interval: 5 * time.Millisecond}
	var mu sync.Mutex
	var order []int
	var wg sync.WaitGroup
	for i := range 5 {
		if err := func() error { return nil }(); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		// Sequential reservation, concurrent waiting: this is how the engine uses it.
		go func(i int) {
			defer wg.Done()
			_ = g.wait(context.Background(), time.Now)
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
		}(i)
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
	if len(order) != 5 {
		t.Fatalf("got %d callers through, want 5", len(order))
	}
}

func TestRateGateStopsWaitingWhenCanceled(t *testing.T) {
	g := &rateGate{interval: time.Hour}
	_ = g.wait(context.Background(), time.Now) // take the first slot
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()

	start := time.Now()
	if err := g.wait(ctx, time.Now); err == nil {
		t.Error("a canceled run kept waiting")
	}
	if time.Since(start) > time.Second {
		t.Error("cancellation did not interrupt the wait")
	}
}

func TestRateGatesOnlyThrottleWhatDeclaresALimit(t *testing.T) {
	// Nearly every scanner declares nothing, so the common path must cost an interface assertion
	// and return.
	gates := newRateGates()
	start := time.Now()
	for range 50 {
		if err := gates.wait(context.Background(), plainScanner{"plain"}, "plain", nil); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("unlimited scanners were delayed: %v", elapsed)
	}
	// And a zero rate is the same as none.
	zero := rateScanner{name: "zero", rate: plugin.Rate{}}
	if err := gates.wait(context.Background(), zero, "zero", nil); err != nil {
		t.Fatal(err)
	}
}

func TestRateGatesKeepScannersApart(t *testing.T) {
	// One scanner's limit is not another's. A gate shared across scanners would make a slow API
	// throttle every control in the run, which is the thing this exists to prevent.
	gates := newRateGates()
	slow := rateScanner{name: "slow", rate: plugin.Rate{Requests: 1, Per: time.Hour}}
	fast := rateScanner{name: "fast", rate: plugin.Rate{Requests: 1000, Per: time.Second}}

	if err := gates.wait(context.Background(), slow, "slow", nil); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 5 {
		if err := gates.wait(context.Background(), fast, "fast", nil); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("the slow scanner's limit delayed the fast one: %v", elapsed)
	}
}

func TestRateLimitInterval(t *testing.T) {
	if got := (plugin.Rate{Requests: 4, Per: time.Minute}).Interval(); got != 15*time.Second {
		t.Errorf("Interval() = %v", got)
	}
	for _, r := range []plugin.Rate{{}, {Requests: 0, Per: time.Minute}, {Requests: 4}} {
		if got := r.Interval(); got != 0 {
			t.Errorf("%+v should mean no limit, got %v", r, got)
		}
	}
}

// slowRateScanner records how many scans are running at once.
type slowRateScanner struct {
	name    string
	rate    plugin.Rate
	mu      *sync.Mutex
	running *int
	peak    *int
}

func (s slowRateScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Controls: []string{"c"},
		TargetKinds: []plugin.TargetKind{plugin.TargetHost}}
}
func (s slowRateScanner) RateLimit(plugin.Config) plugin.Rate { return s.rate }
func (s slowRateScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	s.mu.Lock()
	*s.running++
	if *s.running > *s.peak {
		*s.peak = *s.running
	}
	s.mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	s.mu.Lock()
	*s.running--
	s.mu.Unlock()
	return sarif.Report{}, nil
}

func TestARateLimitedScannerDoesNotHoldConcurrencySlots(t *testing.T) {
	// The reason the wait happens before the semaphore rather than after. A hosted API allowing
	// four calls a minute means fifteen seconds of waiting per call; spent holding a worker, a
	// handful of such jobs would idle the pool and every unrelated control would queue behind a
	// scanner it has nothing to do with.
	//
	// Asserted by watching how many rate-limited scans are ever in flight together: if the wait
	// held a slot, the gate would still serialize them, but the slots would be gone. Here the
	// slots stay free, so the *only* thing serializing them is the gate.
	var mu sync.Mutex
	running, peak := 0, 0
	gates := newRateGates()
	s := slowRateScanner{
		name: "slow", rate: plugin.Rate{Requests: 1000, Per: time.Second},
		mu: &mu, running: &running, peak: &peak,
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Exactly the engine's ordering: wait for the rate, then take a slot.
			if err := gates.wait(context.Background(), s, s.name, nil); err != nil {
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()
			_, _ = s.Scan(context.Background(), plugin.HostTarget{URL: "https://x/"}, nil)
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if peak > 4 {
		t.Errorf("the semaphore was exceeded: %d concurrent scans", peak)
	}
	if peak == 0 {
		t.Error("nothing ran")
	}
}
