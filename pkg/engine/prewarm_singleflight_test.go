package engine

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

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

	// Two components, identical target → one scan, and two findings.
	//
	// The scan is shared because the work is identical; the findings are not, because the components
	// are not. Each carries its own component's exposure and criticality, so the same flaw can be P1
	// for one and P4 for the other. Collapsing them would keep whichever merged first and silently
	// drop the other.
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
	// One per component: the saving is in the scanning, not in the reporting.
	if got := res.Controls["images"].Report.Counts().Warning; got != 2 {
		t.Errorf("merged warnings = %d, want one per component", got)
	}
}

// Two components on one repository that ignore different parts of it are two scans, each handed
// its own component's ignore list. One scan shared between them reads a tree only one of them
// declared, and reports a directory the other ignores as that component's finding.
func TestComponentsIgnoringDifferentPartsOfOneRepositoryScanSeparately(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "mod"})
	sc := &moduleScanner{}
	reg.RegisterScanner(sc)
	m := saga.Model{
		Release: saga.Release{Version: "1"},
		Config:  saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "web", Repositories: []saga.Repository{{URL: "https://git/mono", Revision: "v2", Ignore: []string{"services/api/"}}}},
			{Name: "api", Repositories: []saga.Repository{{URL: "https://git/mono", Revision: "v2", Ignore: []string{"services/web/"}}}},
		},
	}

	// No module resolver, so each job keeps the scope its component declared.
	res, err := New(reg).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Scans != 2 || res.Stats.Deduped != 0 {
		t.Errorf("stats = %+v, want Scans=2 Deduped=0", res.Stats)
	}
	var ignored []string
	for _, target := range sc.targets {
		ignored = append(ignored, strings.Join(target.Ignore, ","))
	}
	slices.Sort(ignored)
	if want := []string{"services/api/", "services/web/"}; !slices.Equal(ignored, want) {
		t.Errorf("the scanner was handed ignore lists %q, want %q", ignored, want)
	}
}

func TestSingleflightGroupRunsOnce(t *testing.T) {
	// Callers arriving while the first is still running wait for its result and do not run the work
	// again. The first caller's work blocks until every other caller has started, so they arrive
	// while it is in flight on any schedule.
	const followers = 11
	g := &sfGroup{}
	var calls atomic.Int32
	inFlight := make(chan struct{})
	release := make(chan struct{})
	leader := make(chan bool)
	go func() {
		_, shared, _ := g.do("k", func() (any, error) {
			calls.Add(1)
			close(inFlight)
			<-release
			return "v", nil
		})
		leader <- shared
	}()
	<-inFlight

	var started, wg sync.WaitGroup
	var returned atomic.Int32
	vals := make([]any, followers)
	shared := make([]bool, followers)
	for i := range followers {
		started.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			started.Done()
			vals[i], shared[i], _ = g.do("k", func() (any, error) {
				calls.Add(1)
				return "ran again", nil
			})
			returned.Add(1)
		}()
	}
	started.Wait()
	// Nothing can have returned yet, because the only value to return is still being computed.
	if n := returned.Load(); n != 0 {
		t.Errorf("%d callers returned while the first was still running", n)
	}
	close(release)
	wg.Wait()

	if <-leader {
		t.Error("the caller that ran the work reported it as shared")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("the work ran %d times, want 1", n)
	}
	for i := range followers {
		if !shared[i] || vals[i] != "v" {
			t.Errorf("caller %d: shared=%v value=%v, want the first caller's result", i, shared[i], vals[i])
		}
	}
}
