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

func TestTheVersionProbeRunsWhetherOrNotCachingIsOn(t *testing.T) {
	newReg := func(sc plugin.Scanner) *Registry {
		reg := NewRegistry()
		reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
		reg.RegisterScanner(sc)
		return reg
	}

	// Without a cache there is no key to build, and the probe still runs: the report has to say
	// what produced it, and most runs do not cache.
	noCache := &versionedScanner{name: "s", version: "db@1"}
	res, err := New(newReg(noCache)).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	if noCache.versionCalls() == 0 {
		t.Error("the version was never asked for, so the report cannot say what ran")
	}
	if got := provenanceVersion(res, "s"); got != "db@1" {
		t.Errorf("provenance version = %q, want %q", got, "db@1")
	}

	// With a cache it runs as it always did, and the key is built from it.
	withCache := &versionedScanner{name: "s", version: "db@1"}
	if _, err := New(newReg(withCache), WithCache(cache.NewMemory())).Run(context.Background(), model()); err != nil {
		t.Fatal(err)
	}
	if withCache.versionCalls() == 0 {
		t.Error("CacheVersion should be probed when caching is enabled")
	}
}

// A version nothing could read is recorded as absent. A placeholder would make two genuinely
// different tools look identical to whoever compares two reports later.
func TestAnUnreadableVersionIsAbsentRatherThanInvented(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&versionedScanner{name: "s", version: ""})
	res, err := New(reg).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	if got := provenanceVersion(res, "s"); got != "" {
		t.Errorf("provenance version = %q, want nothing", got)
	}
}

// provenanceVersion is what the run recorded as the version of one scanner, or "" where it
// recorded none.
func provenanceVersion(res Result, tool string) string {
	for _, cr := range res.Controls {
		for _, p := range cr.Report.Provenance {
			if p.Tool == tool {
				return p.Version
			}
		}
	}
	return ""
}
