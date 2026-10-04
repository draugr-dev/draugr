package engine

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
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
		t.Errorf("four calls took %v, they were not spaced", elapsed)
	}
}

func TestRateGateServesCallersInOrder(t *testing.T) {
	// Each caller reserves its slot and releases the lock, so a later arrival cannot overtake an
	// earlier one and no caller is starved while others keep arriving.
	//
	// The clock fixes the arrival order. The gate reads it once, under its lock, while reserving, so
	// a caller blocked in the clock holds the lock and the next caller cannot reserve until it lets
	// go. The clock stands still, so each reservation is exactly one interval after the previous one
	// on any machine.
	const callers = 5
	g := &rateGate{interval: 20 * time.Millisecond}
	base := time.Now()
	reserving := make(chan struct{})
	clock := func() time.Time {
		reserving <- struct{}{}
		return base
	}

	var mu sync.Mutex
	var order []int
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		// Sequential reservation, concurrent waiting: this is how the engine uses it.
		go func() {
			defer wg.Done()
			if err := g.wait(context.Background(), clock); err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
		}()
		<-reserving
	}
	wg.Wait()

	want := make([]int, callers)
	for i := range want {
		want[i] = i
	}
	if !slices.Equal(order, want) {
		t.Errorf("callers were served in the order %v, want arrival order %v", order, want)
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

// hostedScanner stands in for a scanner calling a hosted API that publishes a limit.
type hostedScanner struct {
	rate plugin.Rate
	mu   sync.Mutex
	call int
}

func (s *hostedScanner) Info() plugin.ScannerInfo            { return plugin.ScannerInfo{Name: "hosted"} }
func (s *hostedScanner) RateLimit(plugin.Config) plugin.Rate { return s.rate }
func (s *hostedScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	s.mu.Lock()
	s.call++
	s.mu.Unlock()
	return sarif.Report{}, nil
}

func (s *hostedScanner) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.call
}

// poolScanner holds each call open until size of them are in flight at once, so it can only finish
// on a pool with size slots free to it.
type poolScanner struct {
	name    string
	size    int
	full    chan struct{}
	mu      sync.Mutex
	running int
	peak    int
}

func (s *poolScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }
func (s *poolScanner) Scan(ctx context.Context, _ plugin.Target, _ plugin.Config) (sarif.Report, error) {
	s.mu.Lock()
	s.running++
	if s.running > s.peak {
		s.peak = s.running
		if s.peak == s.size {
			close(s.full)
		}
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running--
		s.mu.Unlock()
	}()
	select {
	case <-s.full:
		return sarif.Report{}, nil
	case <-ctx.Done():
		return sarif.Report{}, ctx.Err()
	}
}

func (s *poolScanner) peakRunning() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

func TestARateLimitedScannerDoesNotHoldConcurrencySlots(t *testing.T) {
	// The reason the wait happens before the semaphore rather than after. A hosted API allowing
	// four calls a minute means fifteen seconds of waiting per call; spent holding a worker, a
	// handful of such jobs would idle the pool and every unrelated control would queue behind a
	// scanner it has nothing to do with.
	//
	// The test drives Run with more rate-limited jobs than the pool has slots. The gate lets the
	// first call through and holds the rest for an hour. The unrelated scanner finishes only once it
	// has every slot at the same moment, so a single waiter holding one is enough to stop it.
	//
	// On one processor, goroutines start in the order Run creates them. "hosted" sorts before
	// "images", so its jobs are planned first and its waiters reach the pool before the unrelated
	// jobs do. With several processors an unrelated job can get there first and fill the pool before
	// any waiter arrives, which passes whichever order the engine used. The engine's own order passes
	// on any schedule, so one processor removes only that false pass.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	const components, pool = 4, 2
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "hosted", scope: plugin.ScopeComponent, scanner: "hosted"})
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	hosted := &hostedScanner{rate: plugin.Rate{Requests: 1, Per: time.Hour}}
	unrelated := &poolScanner{name: "s", size: pool, full: make(chan struct{})}
	reg.RegisterScanner(hosted)
	reg.RegisterScanner(unrelated)

	m := saga.Model{
		Release: saga.Release{Version: "1"},
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"hosted": {"enabled": true},
			"images": {"enabled": true},
		}},
	}
	for i := range components {
		m.Components = append(m.Components, saga.Component{Name: fmt.Sprintf("c%d", i)})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = New(reg, WithConcurrency(pool)).Run(ctx, m)
	}()

	select {
	case <-unrelated.full:
	case <-time.After(10 * time.Second):
		t.Errorf("unrelated jobs reached %d of the pool's %d slots while the rate-limited ones waited: "+
			"the waiters held the rest", unrelated.peakRunning(), pool)
	}
	// Ends the hour-long waits, which are all that is left of the run.
	cancel()
	<-finished

	// One call through and the rest held is the state the pool check depends on. A gate that never
	// engaged would leave nothing waiting, and the unrelated jobs would finish regardless.
	if got := hosted.calls(); got != 1 {
		t.Errorf("the rate-limited scanner ran %d times, want 1: the gate did not hold the rest", got)
	}
}
