package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// boundScanner records the bound each of its jobs' tools would get, and holds every job until
// hold of them have started, so the jobs a test means to overlap do.
type boundScanner struct {
	name      string
	exclusive string
	mu        sync.Mutex
	bounds    []int
	started   *sync.WaitGroup
}

func (s *boundScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Version: "1", Exclusive: s.exclusive}
}

func (s *boundScanner) Scan(ctx context.Context, _ plugin.Target, _ plugin.Config) (sarif.Report, error) {
	s.mu.Lock()
	s.bounds = append(s.bounds, toolexec.Bound(ctx))
	s.mu.Unlock()
	if s.started != nil {
		s.started.Done()
		s.started.Wait()
	}
	return sarif.Report{Tool: s.name}, nil
}

// boundController plans one job per component for its scanner.
type boundController struct{ scanner string }

func (boundController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "bound", Scope: plugin.ScopeComponent}
}

func (c boundController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	return []plugin.ScanJob{{Scanner: c.scanner, Target: plugin.ImageTarget{Ref: comp.Name}}}, nil
}

func (boundController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "bound", Report: sarif.Merge(reports...)}, nil
}

func boundModel() saga.Model {
	return saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"bound": {"enabled": true}}},
		Components: []saga.Component{{Name: "web"}, {Name: "api"}},
	}
}

func TestTwoJobsRunningAtOnceShareTheBound(t *testing.T) {
	n := toolexec.Parallelism()
	var started sync.WaitGroup
	started.Add(2)
	s := &boundScanner{name: "fake", started: &started}
	reg := NewRegistry()
	reg.RegisterController(boundController{scanner: "fake"})
	reg.RegisterScanner(s)

	if _, err := New(reg, WithConcurrency(2)).Run(context.Background(), boundModel()); err != nil {
		t.Fatal(err)
	}
	for _, b := range s.bounds {
		if want := max(1, n/2); b != want {
			t.Errorf("bounds = %v, want each job's tools given %d of %d", s.bounds, want, n)
		}
	}
}

func TestAJobRunningAloneKeepsTheWholeBound(t *testing.T) {
	// One at a time, by -j 1 or because the jobs take turns at a resource: no job runs beside
	// another, so each keeps the bound whole.
	n := toolexec.Parallelism()
	for name, opts := range map[string]struct {
		jobs      int
		exclusive string
	}{
		"-j 1":                      {jobs: 1},
		"jobs taking turns at -j 2": {jobs: 2, exclusive: plugin.ExclusiveGoPackageLoad},
	} {
		s := &boundScanner{name: "fake", exclusive: opts.exclusive}
		reg := NewRegistry()
		reg.RegisterController(boundController{scanner: "fake"})
		reg.RegisterScanner(s)
		if _, err := New(reg, WithConcurrency(opts.jobs)).Run(context.Background(), boundModel()); err != nil {
			t.Fatal(err)
		}
		if len(s.bounds) != 2 || s.bounds[0] != n || s.bounds[1] != n {
			t.Errorf("%s: bounds = %v, want the whole bound %d for both", name, s.bounds, n)
		}
	}
}

func TestJobsTakingTurnsCountOnceBesideTheOthers(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(&boundScanner{name: "gosec", exclusive: plugin.ExclusiveGoPackageLoad})
	reg.RegisterScanner(&boundScanner{name: "govulncheck", exclusive: plugin.ExclusiveGoPackageLoad})
	reg.RegisterScanner(&boundScanner{name: "trivy"})
	var planned []PlannedJob
	for _, sc := range []string{"gosec", "gosec", "govulncheck", "trivy", "trivy"} {
		planned = append(planned, PlannedJob{Job: plugin.ScanJob{Scanner: sc}})
	}
	u := newUnfinishedJobs(reg, planned)
	if got := u.atOnce(); got != 3 {
		t.Errorf("atOnce = %d, want 3: two trivy jobs and one turn at the Go package load", got)
	}
	u.finish("gosec")
	u.finish("gosec")
	u.finish("govulncheck")
	if got := u.atOnce(); got != 2 {
		t.Errorf("atOnce = %d after the Go package loads ended, want 2", got)
	}
	u.finish("trivy")
	if got := u.atOnce(); got != 1 {
		t.Errorf("atOnce = %d with one job left, want 1", got)
	}
}

func TestTheDefaultJobCountIsTheMachines(t *testing.T) {
	orig := defaultConcurrency
	t.Cleanup(func() { defaultConcurrency = orig })
	defaultConcurrency = func() int { return 3 }
	if got := New(NewRegistry()).concurrency; got != 3 {
		t.Errorf("concurrency = %d, want the machine's default 3", got)
	}
}
