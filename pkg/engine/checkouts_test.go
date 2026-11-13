package engine

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// checkoutLog stands in for git: each checkout is a real directory, so a test can tell one that was
// removed from one that was not, and it counts how often each key was materialized.
type checkoutLog struct {
	t            *testing.T
	mu           sync.Mutex
	materialized map[string]int
	dirs         map[string]string
	// readWhileGone records a scanner that found its checkout removed while it was reading it.
	readWhileGone []string
}

func newCheckoutLog(t *testing.T) *checkoutLog {
	return &checkoutLog{t: t, materialized: map[string]int{}, dirs: map[string]string{}}
}

// checkout reads key's tree through the run's pool, as a repository scanner does.
func (l *checkoutLog) checkout(ctx context.Context, key string) error {
	tree, release, err := git.PoolFrom(ctx).Checkout(ctx, key, func(context.Context) (git.Tree, func(), error) {
		dir, err := os.MkdirTemp("", "checkouts-test-")
		if err != nil {
			return git.Tree{}, nil, err
		}
		l.mu.Lock()
		l.materialized[key]++
		l.dirs[key] = dir
		l.mu.Unlock()
		return git.Tree{Dir: dir}, func() { _ = os.RemoveAll(dir) }, nil
	})
	if err != nil {
		return err
	}
	defer release()
	if _, err := os.Stat(tree.Dir); err != nil {
		l.mu.Lock()
		l.readWhileGone = append(l.readWhileGone, key)
		l.mu.Unlock()
	}
	return nil
}

// left lists the checkouts still on disk.
func (l *checkoutLog) left() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for key, dir := range l.dirs {
		if _, err := os.Stat(dir); err == nil {
			out = append(out, key)
		}
	}
	return out
}

// checkoutScanner reads its repository through the pool under the key a repository scanner uses, and
// reads history when history is set.
type checkoutScanner struct {
	name    string
	history bool
	log     *checkoutLog
}

func (s checkoutScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Version: "1"}
}

func (s checkoutScanner) ReadsHistory(plugin.Config) bool { return s.history }

func (s checkoutScanner) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	repo := target.(plugin.RepositoryTarget)
	scope := git.Scope{Paths: repo.Paths, Ignore: repo.Ignore, History: s.history}
	if err := s.log.checkout(ctx, git.Key(repo.URL, repo.Revision, repo.WorkingTree, scope)); err != nil {
		return sarif.Report{}, err
	}
	return sarif.Report{Tool: s.name}, nil
}

// checkoutController plans one job per scanner for each repository a component declares.
type checkoutController struct{ scanners []string }

func (checkoutController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "checkouts", Scope: plugin.ScopeComponent}
}

func (c checkoutController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		for _, sc := range c.scanners {
			jobs = append(jobs, plugin.ScanJob{Scanner: sc, Target: plugin.RepositoryTarget{URL: r.URL}})
		}
	}
	return jobs, nil
}

func (checkoutController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "checkouts", Report: sarif.Merge(reports...)}, nil
}

// twoCheckedOutRepositories is a run over two repositories, each read by two tree scanners and one history
// scanner: four checkouts, two of them shared by two jobs.
func twoCheckedOutRepositories(t *testing.T, sbomOn bool) (*Registry, saga.Model, *checkoutLog) {
	t.Helper()
	log := newCheckoutLog(t)
	reg := NewRegistry()
	reg.RegisterController(checkoutController{scanners: []string{"tree-a", "tree-b", "history"}})
	reg.RegisterScanner(checkoutScanner{name: "tree-a", log: log})
	reg.RegisterScanner(checkoutScanner{name: "tree-b", log: log})
	reg.RegisterScanner(checkoutScanner{name: "history", history: true, log: log})
	m := saga.Model{
		Release: saga.Release{Version: "1"},
		Config:  saga.Config{Controls: map[string]saga.ControllerSettings{"checkouts": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "web", Repositories: []saga.Repository{{URL: "/src/web"}}},
			{Name: "api", Repositories: []saga.Repository{{URL: "/src/api"}}},
		},
	}
	if sbomOn {
		m.Config.SBOM = &saga.SBOMConfig{Enabled: true, Format: saga.SBOMCycloneDXJSON}
	}
	return reg, m, log
}

func TestARunRemovesEachCheckoutWhenItsLastJobEnds(t *testing.T) {
	for _, concurrency := range []int{1, 6} {
		reg, m, log := twoCheckedOutRepositories(t, false)
		pool := git.NewPool()
		ctx := git.WithPool(context.Background(), pool)

		if _, err := New(reg, WithConcurrency(concurrency)).Run(ctx, m); err != nil {
			t.Fatal(err)
		}
		// Before Close: what is gone now went when its last job did, not when the run ended.
		if left := log.left(); len(left) != 0 {
			t.Errorf("concurrency %d: checkouts still on disk after every job ended: %v", concurrency, left)
		}
		if len(log.readWhileGone) != 0 {
			t.Errorf("concurrency %d: removed while a job was reading it: %v", concurrency, log.readWhileGone)
		}
		// Two repositories, each a tree and a history: four checkouts, each made once, the tree
		// shared by two scanners even when they ran one after the other.
		if len(log.materialized) != 4 {
			t.Errorf("concurrency %d: %d checkouts, want 4: %v", concurrency, len(log.materialized), log.materialized)
		}
		for key, n := range log.materialized {
			if n != 1 {
				t.Errorf("concurrency %d: %s materialized %d times, want 1", concurrency, key, n)
			}
		}
		pool.Close()
	}
}

// poolSBOM inventories a repository through the pool, as the Syft generator does.
type poolSBOM struct {
	log   *checkoutLog
	calls int
}

func (g *poolSBOM) Generate(ctx context.Context, component string, t plugin.Target, format saga.SBOMFormat) (sbom.Document, error) {
	g.calls++
	if key, ok := sbomCheckoutKey(t); ok {
		if err := g.log.checkout(ctx, key); err != nil {
			return sbom.Document{}, err
		}
	}
	return sbom.Document{Component: component, Target: t.Identity(), Format: format, Bytes: []byte("{}")}, nil
}

func TestAnSBOMReadsTheTreeTheScannersRead(t *testing.T) {
	reg, m, log := twoCheckedOutRepositories(t, true)
	gen := &poolSBOM{log: log}
	pool := git.NewPool()
	defer pool.Close()
	ctx := git.WithPool(context.Background(), pool)

	if _, err := New(reg, WithSBOM(gen)).Run(ctx, m); err != nil {
		t.Fatal(err)
	}
	if gen.calls != 2 {
		t.Fatalf("SBOMs generated = %d, want 2", gen.calls)
	}
	// The SBOM is generated after every scan has ended, and it still found the tree checkouts the
	// scanners made, because it had declared that it would read them.
	for key, n := range log.materialized {
		if n != 1 {
			t.Errorf("%s materialized %d times, want 1: the SBOM made its own", key, n)
		}
	}
	if left := log.left(); len(left) != 0 {
		t.Errorf("checkouts still on disk after the SBOMs: %v", left)
	}
}

func TestARunWithoutAPoolDeclaresNothing(t *testing.T) {
	reg, m, _ := twoCheckedOutRepositories(t, false)
	e := New(reg)
	planned, err := e.Plan(m)
	if err != nil {
		t.Fatal(err)
	}
	if keys := e.declareCheckouts(context.Background(), planned, m); keys != nil {
		t.Errorf("declared %v with no pool to declare to", keys)
	}
}
