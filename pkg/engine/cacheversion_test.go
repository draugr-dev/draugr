package engine

import (
	"context"
	"regexp"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Two Draugr builds sharing one cache directory never read each other's entries, and each still
// reads its own. Every other input to the key is identical across the four runs.
func TestACacheEntryIsNotServedToAnotherDraugrBuild(t *testing.T) {
	dir := t.TempDir()
	run := func(build string) (Stats, int) {
		t.Helper()
		reg := NewRegistry()
		reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
		sc := &fakeScanner{name: "s"}
		reg.RegisterScanner(sc)
		e := New(reg, WithCache(cache.NewLocal(dir, 0)))
		e.build = build
		res, err := e.Run(context.Background(), model())
		if err != nil {
			t.Fatal(err)
		}
		return res.Stats, sc.calls()
	}

	for _, step := range []struct {
		build       string
		scans, hits int
	}{
		{"0.158.0+1a2b3c4d", 2, 0},
		{"0.158.1+5e6f7a8b", 2, 0},
		{"0.158.0+1a2b3c4d", 0, 2},
		{"0.158.1+5e6f7a8b", 0, 2},
	} {
		stats, calls := run(step.build)
		if stats.Scans != step.scans || stats.CacheHits != step.hits || calls != step.scans {
			t.Errorf("build %s: scans = %d, hits = %d, scanner calls = %d; want %d scans, %d hits",
				step.build, stats.Scans, stats.CacheHits, calls, step.scans, step.hits)
		}
	}
}

// An engine keys on the binary it runs in, unless a test says otherwise.
func TestAnEngineKeysOnTheRunningBuild(t *testing.T) {
	if got := New(NewRegistry()).build; got != version.Build() {
		t.Errorf("build = %q, want %q", got, version.Build())
	}
}

// The scoped key differs per build and stays a plain hex name, so the revision can still be
// appended after an "@" and the entry stored under its own file name.
func TestBuildScopedKeyIsAHexNamePerBuild(t *testing.T) {
	a, b := buildScopedKey("k", "0.158.0+none"), buildScopedKey("k", "0.158.1+none")
	if a == b {
		t.Error("two builds produced one key")
	}
	if a != buildScopedKey("k", "0.158.0+none") {
		t.Error("the same build produced two keys")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a) {
		t.Errorf("key = %q, want 64 hex characters", a)
	}
}

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
