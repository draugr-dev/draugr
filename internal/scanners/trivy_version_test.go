package scanners

import (
	"context"
	"errors"
	"testing"
)

func TestTrivyVersionProbe(t *testing.T) {
	const out = `{"Version":"0.69.3","VulnerabilityDB":{"UpdatedAt":"2026-07-15T00:56:58Z"}}`
	p := &trivyVersionProbe{run: func(context.Context, []string) ([]byte, error) { return []byte(out), nil }}
	if got := p.cacheVersion(context.Background()); got != "trivy@0.69.3;db@2026-07-15T00:56:58Z" {
		t.Errorf("cacheVersion = %q", got)
	}
	// Memoized: a second call returns the same value without re-running.
	if got := p.cacheVersion(context.Background()); got != "trivy@0.69.3;db@2026-07-15T00:56:58Z" {
		t.Errorf("memoized cacheVersion = %q", got)
	}
}

func TestTrivyVersionProbeErrors(t *testing.T) {
	// Probe failure → empty (graceful; key falls back to version-less).
	pErr := &trivyVersionProbe{run: func(context.Context, []string) ([]byte, error) { return nil, errors.New("no trivy") }}
	if got := pErr.cacheVersion(context.Background()); got != "" {
		t.Errorf("error path should yield empty, got %q", got)
	}
	// Unparseable / empty version → empty.
	pBad := &trivyVersionProbe{run: func(context.Context, []string) ([]byte, error) { return []byte("not json"), nil }}
	if got := pBad.cacheVersion(context.Background()); got != "" {
		t.Errorf("bad output should yield empty, got %q", got)
	}
}

func TestRepoScannerCacheVersion(t *testing.T) {
	// trivy-fs wires the shared probe → implements CacheVersioner (non-panicking).
	if _, ok := NewTrivyFS().(interface {
		CacheVersion(context.Context) string
	}); !ok {
		t.Error("trivy-fs should implement CacheVersioner")
	}
	// gitleaks has no dynamic version → CacheVersion returns "".
	if s, ok := NewGitleaks().(interface {
		CacheVersion(context.Context) string
	}); !ok || s.CacheVersion(context.Background()) != "" {
		t.Error("gitleaks CacheVersion should be empty")
	}
}

func TestTrivyDBWarmerMemoized(t *testing.T) {
	var calls int
	w := &trivyDBWarmer{run: func(context.Context, []string) ([]byte, error) { calls++; return nil, nil }}
	_ = w.warm(context.Background())
	_ = w.warm(context.Background())
	if calls != 1 {
		t.Errorf("warm should run once (memoized), got %d", calls)
	}
}

func TestTrivyDBWarmerError(t *testing.T) {
	w := &trivyDBWarmer{run: func(context.Context, []string) ([]byte, error) { return nil, errors.New("no trivy") }}
	if err := w.warm(context.Background()); err == nil {
		t.Error("warm should surface the run error")
	}
}

func TestRepoScannerPrewarm(t *testing.T) {
	// trivy-fs wires the shared warmer → implements Prewarmer.
	if _, ok := NewTrivyFS().(interface {
		Prewarm(context.Context) error
	}); !ok {
		t.Error("trivy-fs should implement Prewarmer")
	}
	// gitleaks has nothing to warm → Prewarm is a no-op returning nil.
	if s, ok := NewGitleaks().(interface {
		Prewarm(context.Context) error
	}); !ok || s.Prewarm(context.Background()) != nil {
		t.Error("gitleaks Prewarm should be a nil-returning no-op")
	}
}
