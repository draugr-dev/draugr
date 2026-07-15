package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// versionedScanner implements plugin.CacheVersioner and records how often CacheVersion runs.
type versionedScanner struct {
	name    string
	version string
	mu      sync.Mutex
	vcalls  int
}

func (f *versionedScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: f.name} }

func (f *versionedScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: f.name, Results: []sarif.Result{
		{RuleID: "R", Level: sarif.LevelWarning, Location: sarif.Location{URI: target.Identity()}},
	}}, nil
}

func (f *versionedScanner) CacheVersion(context.Context) string {
	f.mu.Lock()
	f.vcalls++
	f.mu.Unlock()
	return f.version
}

func (f *versionedScanner) versionCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vcalls
}

func TestEffectiveKeyUsesCacheVersioner(t *testing.T) {
	ctx := context.Background()
	job := plugin.ScanJob{Scanner: "s", Target: plugin.RepositoryTarget{URL: "u"}}

	// No CacheVersioner, no Info().Version → version-less key.
	base := effectiveKey(ctx, job, &fakeScanner{name: "s"})

	// Different CacheVersion values produce different keys...
	k1 := effectiveKey(ctx, job, &versionedScanner{name: "s", version: "db@1"})
	k2 := effectiveKey(ctx, job, &versionedScanner{name: "s", version: "db@2"})
	if k1 == k2 {
		t.Error("different CacheVersion should yield different cache keys")
	}
	if k1 == base {
		t.Error("a CacheVersioner should change the key versus the version-less key")
	}

	// ...and an empty CacheVersion falls back to the version-less key.
	if got := effectiveKey(ctx, job, &versionedScanner{name: "s", version: ""}); got != base {
		t.Error("empty CacheVersion should match the version-less key")
	}

	// A preset CacheKey always wins.
	preset := plugin.ScanJob{Scanner: "s", Target: plugin.RepositoryTarget{URL: "u"}, CacheKey: "PRESET"}
	if got := effectiveKey(ctx, preset, &versionedScanner{name: "s", version: "db@1"}); got != "PRESET" {
		t.Errorf("preset CacheKey should win, got %q", got)
	}
}

func TestCacheVersionProbedOnlyWhenCaching(t *testing.T) {
	newReg := func(sc plugin.Scanner) *Registry {
		reg := NewRegistry()
		reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
		reg.RegisterScanner(sc)
		return reg
	}

	// No cache → the version probe must never run.
	noCache := &versionedScanner{name: "s", version: "db@1"}
	if _, err := New(newReg(noCache)).Run(context.Background(), model()); err != nil {
		t.Fatal(err)
	}
	if noCache.versionCalls() != 0 {
		t.Errorf("CacheVersion should not be probed without caching, got %d calls", noCache.versionCalls())
	}

	// With cache → the probe runs (to build the key).
	withCache := &versionedScanner{name: "s", version: "db@1"}
	if _, err := New(newReg(withCache), WithCache(cache.NewMemory())).Run(context.Background(), model()); err != nil {
		t.Fatal(err)
	}
	if withCache.versionCalls() == 0 {
		t.Error("CacheVersion should be probed when caching is enabled")
	}
}
