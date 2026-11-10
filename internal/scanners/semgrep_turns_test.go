package scanners

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Three repositories with room for every job at once: the Semgrep runs still go one at a time,
// because each sizes its analysis to the whole machine and Semgrep's per-function time limits cut
// short a run that shares it. Each repository is scanned.
func TestSemgrepRunsTakeTurns(t *testing.T) {
	repos := []string{"one", "two", "three"}
	dirs := map[string]string{}
	for _, r := range repos {
		dirs[r] = t.TempDir()
	}
	var running, most atomic.Int32
	var mu sync.Mutex
	scanned := map[string]bool{}
	s := NewSemgrep().(repoScanner)
	s.cacheVersion = func(context.Context) string { return "semgrep@1.182.1" }
	s.checkout = func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}
	inner := fakeSemgrep(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},"results":[]}]}`, noSemgrepResults, nil)
	s.run = func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		n := running.Add(1)
		defer running.Add(-1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		// Long enough that a second run started beside this one would be seen.
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		scanned[dir] = true
		mu.Unlock()
		return inner(ctx, dir, argv)
	}

	reg := engine.NewRegistry()
	reg.RegisterController(sastController{scanner: "semgrep"})
	reg.RegisterScanner(s)
	var comps []saga.Component
	for _, r := range repos {
		comps = append(comps, saga.Component{Name: r, Repositories: []saga.Repository{{URL: r}}})
	}
	model := saga.Model{
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true}}},
		Components: comps,
	}
	if _, err := engine.New(reg, engine.WithConcurrency(len(repos))).Run(context.Background(), model); err != nil {
		t.Fatal(err)
	}
	if got := most.Load(); got != 1 {
		t.Errorf("at most %d Semgrep runs at once, want 1", got)
	}
	if len(scanned) != len(repos) {
		t.Errorf("scanned %d repositories, want %d", len(scanned), len(repos))
	}
	if NewSemgrep().Info().Exclusive != plugin.ExclusiveSemgrep {
		t.Error("the scanner does not declare plugin.ExclusiveSemgrep")
	}
}
