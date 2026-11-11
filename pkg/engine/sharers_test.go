package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// sharerScanner records plugin.Sharers for each of its jobs and holds every job until all of the
// run's jobs have started, so the counts it sees are the ones of jobs running side by side.
type sharerScanner struct {
	name      string
	exclusive string
	mu        *sync.Mutex
	seen      map[string][]int
	started   *sync.WaitGroup
	wait      bool
}

func (s sharerScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Controls: []string{"images"},
		TargetKinds: []plugin.TargetKind{plugin.TargetImage}, Exclusive: s.exclusive}
}

func (s sharerScanner) Scan(ctx context.Context, _ plugin.Target, _ plugin.Config) (sarif.Report, error) {
	s.mu.Lock()
	s.seen[s.name] = append(s.seen[s.name], plugin.Sharers(ctx))
	s.mu.Unlock()
	if s.wait {
		s.started.Done()
		s.started.Wait()
	}
	return sarif.Report{Tool: s.name}, nil
}

// sharerController plans one job per image for each scanner it names.
type sharerController struct{ scanners []string }

func (c sharerController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent, DefaultScanners: c.scanners}
}

func (c sharerController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, sc := range c.scanners {
		for _, img := range comp.Images {
			jobs = append(jobs, plugin.ScanJob{Scanner: sc, Target: plugin.ImageTarget{Ref: img.Image}})
		}
	}
	return jobs, nil
}

func (c sharerController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images", Report: sarif.Merge(reports...)}, nil
}

// Three jobs of one scanner running side by side each learn they share the machine with three,
// the one job of another scanner that it is alone, and the jobs of a scanner whose jobs take turns
// that each is alone. With a pool of one, every job is alone.
func TestEveryJobLearnsHowManyRunsOfItsScannerShareTheMachine(t *testing.T) {
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"images": {"enabled": true}}},
		Components: []saga.Component{{Name: "app", Images: []saga.Image{
			{Image: "acme/a:1"}, {Image: "acme/b:1"}, {Image: "acme/c:1"},
		}}},
	}
	run := func(concurrency int, wait bool) map[string][]int {
		var mu sync.Mutex
		var started sync.WaitGroup
		seen := map[string][]int{}
		reg := NewRegistry()
		reg.RegisterController(sharerController{scanners: []string{"wide", "turns"}})
		reg.RegisterScanner(sharerScanner{name: "wide", mu: &mu, seen: seen, started: &started, wait: wait})
		reg.RegisterScanner(sharerScanner{name: "turns", exclusive: "test-resource", mu: &mu, seen: seen, started: &started})
		if wait {
			started.Add(3)
		}
		if _, err := New(reg, WithConcurrency(concurrency)).Run(context.Background(), model); err != nil {
			t.Fatal(err)
		}
		return seen
	}
	seen := run(6, true)
	for _, n := range seen["wide"] {
		if n != 3 {
			t.Errorf("wide jobs side by side saw %v, want 3 each", seen["wide"])
			break
		}
	}
	for _, n := range seen["turns"] {
		if n != 1 {
			t.Errorf("jobs that take turns saw %v, want 1 each", seen["turns"])
			break
		}
	}
	for _, n := range run(1, false)["wide"] {
		if n != 1 {
			t.Errorf("with a pool of one a job saw %d sharers, want 1", n)
		}
	}
}
