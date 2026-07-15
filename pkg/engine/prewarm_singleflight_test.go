package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// prewarmScanner counts scans and prewarms, and implements plugin.Prewarmer.
type prewarmScanner struct {
	name string
	mu   sync.Mutex
	scan int
	warm int
}

func (s *prewarmScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s *prewarmScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	s.mu.Lock()
	s.scan++
	s.mu.Unlock()
	return sarif.Report{Tool: s.name, Results: []sarif.Result{
		{RuleID: "R", Level: sarif.LevelWarning, Location: sarif.Location{URI: target.Identity()}},
	}}, nil
}

func (s *prewarmScanner) Prewarm(context.Context) error {
	s.mu.Lock()
	s.warm++
	s.mu.Unlock()
	return nil
}

func (s *prewarmScanner) counts() (scans, warms int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scan, s.warm
}

// dupController plans the same target for every component, so two components collapse to one scan.
type dupController struct{ scanner string }

func (c dupController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent}
}

func (c dupController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	return []plugin.ScanJob{{Scanner: c.scanner, Target: plugin.ImageTarget{Ref: "same:1"}}}, nil
}

func (c dupController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	return plugin.ControlResult{Control: "images", Report: merged}, nil
}

func TestPrewarmCalledOncePerScanner(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	sc := &prewarmScanner{name: "s"}
	reg.RegisterScanner(sc)

	// model() has two components → two distinct-target jobs for one scanner.
	if _, err := New(reg).Run(context.Background(), model()); err != nil {
		t.Fatal(err)
	}
	scans, warms := sc.counts()
	if warms != 1 {
		t.Errorf("Prewarm should run once per distinct scanner, got %d", warms)
	}
	if scans != 2 {
		t.Errorf("expected 2 scans (distinct targets), got %d", scans)
	}
}

func TestSingleflightCollapsesIdenticalJobs(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(dupController{scanner: "s"})
	sc := &prewarmScanner{name: "s"}
	reg.RegisterScanner(sc)

	// Two components, identical target → one scan, one deduped.
	res, err := New(reg).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	scans, _ := sc.counts()
	if scans != 1 {
		t.Errorf("identical targets should scan once, got %d", scans)
	}
	if res.Stats.Scans != 1 || res.Stats.Deduped != 1 {
		t.Errorf("stats = %+v, want Scans=1 Deduped=1", res.Stats)
	}
	// Both components still get the finding recorded under the control.
	if got := res.Controls["images"].Report.Counts().Warning; got != 1 {
		t.Errorf("merged warnings = %d (deduped by fingerprint), want 1", got)
	}
}

func TestSingleflightGroupRunsOnce(t *testing.T) {
	g := &sfGroup{}
	var calls int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	shared := make([]bool, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, sh, _ := g.do("k", func() (any, error) {
				atomic.AddInt32(&calls, 1)
				time.Sleep(10 * time.Millisecond)
				return "v", nil
			})
			shared[i] = sh
		}(i)
	}
	close(start)
	wg.Wait()
	if calls != 1 {
		t.Errorf("fn ran %d times, want 1", calls)
	}
	leaders := 0
	for _, s := range shared {
		if !s {
			leaders++
		}
	}
	if leaders != 1 {
		t.Errorf("exactly one caller should be the leader, got %d", leaders)
	}
}
