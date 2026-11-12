package scanners

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
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

// TestRepoScannerCacheVersion checks the wiring: a repo scanner whose findings can change when
// its tool changes contributes that tool's version to the cache key, so a cached "no findings"
// cannot outlive the build that produced it.
//
// The value is deliberately not asserted. CacheVersion asks the tool on PATH, so an assertion on
// what it returns is an assertion about the machine: it passes where the tool is absent or built
// without a version stamp, and fails where a real release is installed. Which says nothing about
// the code either way. Extraction from fixed tool output is covered by
// TestToolVersionProbeExtracts.
func TestRepoScannerCacheVersion(t *testing.T) {
	for _, c := range []struct {
		name    string
		scanner plugin.Scanner
	}{
		{"trivy-fs", NewTrivyFS()},
		{"gitleaks", NewGitleaks()},
	} {
		if _, ok := c.scanner.(interface {
			CacheVersion(context.Context) string
		}); !ok {
			t.Errorf("%s should implement CacheVersioner", c.name)
		}
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

// The vuln database and the checks bundle are two downloads into one cache directory, and warming
// the first does nothing for the second. Several `trivy config` jobs against a cold cache race to
// populate it and the losers read a bundle still being written, which surfaces as
// `init Rego scanner: load checks` and reads like a descriptor naming bad Rego.
func TestTrivyChecksWarmFetchesTheBundleOnceAgainstAnEmptyDirectory(t *testing.T) {
	var argvs [][]string
	removed := 0
	w := &trivyChecksWarmer{
		run: func(_ context.Context, argv []string) ([]byte, error) {
			argvs = append(argvs, argv)
			return nil, nil
		},
		dir: func() (string, func(), error) { return "/tmp/empty", func() { removed++ }, nil },
	}
	for range 3 {
		if err := w.warm(context.Background()); err != nil {
			t.Fatalf("warm: %v", err)
		}
	}
	want := [][]string{{"trivy", "config", "--quiet", "/tmp/empty"}}
	if !reflect.DeepEqual(argvs, want) {
		t.Errorf("argv = %v, want %v once", argvs, want)
	}
	// The directory it scans is its own, and it does not outlive the warm.
	if removed != 1 {
		t.Errorf("the temporary directory was cleaned up %d times, want 1", removed)
	}
}

// Best-effort, like the database warm. A warm that cannot run should not stop a scan that might
// still work, and the real problem resurfaces at scan time with the scanner's own message.
func TestTrivyChecksWarmReportsButDoesNotPanicOnAFailedDirectory(t *testing.T) {
	w := &trivyChecksWarmer{
		run: func(context.Context, []string) ([]byte, error) { return nil, nil },
		dir: func() (string, func(), error) { return "", func() {}, errors.New("read-only") },
	}
	if err := w.warm(context.Background()); err == nil {
		t.Error("a directory that could not be made reported success")
	}
}

// fakeTrivy answers `trivy version` with the database date on disk, and `--download-db-only` by
// replacing it, or failing when fail is set.
func fakeTrivy(db *string, fail bool) func(context.Context, []string) ([]byte, error) {
	return func(_ context.Context, argv []string) ([]byte, error) {
		if slices.Contains(argv, "--download-db-only") {
			if fail {
				return nil, errors.New("download failed")
			}
			*db = "2026-11-12T18:57:38Z"
			return nil, nil
		}
		return []byte(`{"Version":"0.76.1","VulnerabilityDB":{"UpdatedAt":"` + *db + `"}}`), nil
	}
}

// The version is first read before the refresh, whose command line depends on it, and the run
// then reads the database the refresh downloaded. The version, which the report and the cache key
// carry, names the one it read.
func TestTrivyVersionNamesTheDatabaseTheRefreshDownloaded(t *testing.T) {
	db := "2026-11-08T18:58:44Z"
	p := &trivyVersionProbe{run: fakeTrivy(&db, false)}
	w := &trivyDBWarmer{run: p.run, version: p.cacheVersion, refreshed: p.reprobe}
	if err := w.warm(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := p.cacheVersion(context.Background()), "trivy@0.76.1;db@2026-11-12T18:57:38Z"; got != want {
		t.Errorf("version after the refresh = %q, want %q", got, want)
	}
}

// A failed download leaves the database that was there, and the version that names it.
func TestTrivyVersionKeepsTheDatabaseAFailedRefreshLeft(t *testing.T) {
	db := "2026-11-08T18:58:44Z"
	p := &trivyVersionProbe{run: fakeTrivy(&db, true)}
	w := &trivyDBWarmer{run: p.run, version: p.cacheVersion, refreshed: p.reprobe}
	if err := w.warm(context.Background()); err == nil {
		t.Fatal("warm should surface the failed download")
	}
	if got, want := p.cacheVersion(context.Background()), "trivy@0.76.1;db@2026-11-08T18:58:44Z"; got != want {
		t.Errorf("version after a failed refresh = %q, want %q", got, want)
	}
}

// An answer that cannot be read after the refresh keeps the one before it rather than blanking the
// version.
func TestTrivyReprobeKeepsAReadableVersion(t *testing.T) {
	calls := 0
	p := &trivyVersionProbe{run: func(context.Context, []string) ([]byte, error) {
		calls++
		if calls > 1 {
			return []byte("not json"), nil
		}
		return []byte(`{"Version":"0.76.1","VulnerabilityDB":{"UpdatedAt":"2026-11-08T18:58:44Z"}}`), nil
	}}
	p.reprobe(context.Background())
	if got := p.cacheVersion(context.Background()); got != "trivy@0.76.1;db@2026-11-08T18:58:44Z" {
		t.Errorf("version = %q, want the readable one kept", got)
	}
}
