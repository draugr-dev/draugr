package engine

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// --- fakes ---

type fakeScanner struct {
	name string
	fail bool
	mu   sync.Mutex
	call int
}

func (f *fakeScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: f.name} }

func (f *fakeScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	f.mu.Lock()
	f.call++
	f.mu.Unlock()
	if f.fail {
		return sarif.Report{}, errors.New("boom")
	}
	// Vary the finding by target so distinct targets don't dedup away.
	return sarif.Report{Tool: f.name, Results: []sarif.Result{
		{RuleID: "R", Level: sarif.LevelWarning, Location: sarif.Location{URI: target.Identity()}},
	}}, nil
}

func (f *fakeScanner) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.call
}

type fakeController struct {
	name     string
	scope    plugin.Scope
	scanner  string
	planFail bool
}

func (c fakeController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: c.scope}
}

func (c fakeController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if c.planFail {
		return nil, errors.New("plan failed")
	}
	var target plugin.Target = plugin.RepositoryTarget{URL: "proj"}
	if c.scope == plugin.ScopeComponent {
		if comp == nil {
			return nil, nil
		}
		target = plugin.ImageTarget{Ref: comp.Name}
	}
	return []plugin.ScanJob{{Scanner: c.scanner, Target: target}}, nil
}

func (c fakeController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	return plugin.ControlResult{
		Control: c.name,
		Report:  merged,
		Summary: plugin.Summary{Warnings: merged.Counts().Warning},
	}, nil
}

func model() saga.Model {
	return saga.Model{
		Release: saga.Release{Version: "1"},
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"images": {"enabled": true},
			"infra":  {"enabled": true},
		}},
		Components: []saga.Component{{Name: "a"}, {Name: "b"}},
	}
}

// --- tests ---

func TestPlanComponentScope(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s"})

	jobs, err := New(reg).Plan(model())
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs (one per component), got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Control != "images" {
			t.Errorf("job control = %q", j.Control)
		}
	}
}

func TestPlanProjectScope(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "infra", scope: plugin.ScopeProject, scanner: "s"})
	jobs, err := New(reg).Plan(model())
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("project-scope should plan 1 job, got %d", len(jobs))
	}
}

func TestPlanSkipsDisabled(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "dast", scope: plugin.ScopeComponent, scanner: "s"})
	jobs, err := New(reg).Plan(model()) // "dast" not enabled in config
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("disabled controller should plan 0 jobs, got %d", len(jobs))
	}
}

func TestPlanControllerError(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s", planFail: true})
	_, err := New(reg).Plan(model())
	if err == nil {
		t.Fatal("expected plan error")
	}
}

func TestRunAggregates(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	sc := &fakeScanner{name: "s"}
	reg.RegisterScanner(sc)

	res, err := New(reg).Run(context.Background(), model())
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	cr, ok := res.Controls["images"]
	if !ok {
		t.Fatal("no images control result")
	}
	if cr.Summary.Warnings != 2 {
		t.Fatalf("want 2 warnings aggregated, got %d", cr.Summary.Warnings)
	}
	if sc.calls() != 2 {
		t.Errorf("scanner should be called twice, got %d", sc.calls())
	}
}

func TestRunScannerNotFound(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "missing"})
	res, err := New(reg).Run(context.Background(), model())
	if err == nil {
		t.Fatal("expected error for missing scanner")
	}
	if len(res.Controls) != 0 {
		t.Errorf("no results expected, got %d", len(res.Controls))
	}
}

func TestRunScanError(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s", fail: true})
	_, err := New(reg).Run(context.Background(), model())
	if err == nil {
		t.Fatal("expected scan error")
	}
}

func TestRunContextCanceled(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := New(reg).Run(ctx, model())
	if err == nil {
		t.Fatal("expected context error")
	}
	if len(res.Controls) != 0 {
		t.Errorf("canceled run should produce no results, got %d", len(res.Controls))
	}
}

func TestWithConcurrencySerialStillCompletes(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	sc := &fakeScanner{name: "s"}
	reg.RegisterScanner(sc)

	// concurrency 0 is ignored (default used); 1 forces serial.
	e := New(reg, WithConcurrency(0), WithConcurrency(1))
	if _, err := e.Run(context.Background(), model()); err != nil {
		t.Fatal(err)
	}
	if sc.calls() != 2 {
		t.Errorf("all jobs should run even serially, got %d calls", sc.calls())
	}
}
