package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// trivyVersionProbe derives a cache-version string for the Trivy-backed scanners that changes
// when the Trivy tool or its vulnerability database updates, so a DB refresh invalidates
// cached results instead of waiting out the TTL. The probe runs `trivy version --format json`
// at most once (memoized); run is injectable for tests.
type trivyVersionProbe struct {
	once sync.Once
	val  string
	run  func(ctx context.Context, argv []string) ([]byte, error)
}

func newTrivyVersionProbe() *trivyVersionProbe {
	return &trivyVersionProbe{run: execArgv}
}

// cacheVersion returns a string like "trivy@0.69.3;db@2026-07-15T00:56:58Z", or "" when the
// version can't be determined (Trivy absent or unexpected output), callers then fall back to
// a version-less cache key.
func (p *trivyVersionProbe) cacheVersion(ctx context.Context) string {
	p.once.Do(func() {
		out, err := p.run(ctx, []string{"trivy", "version", "--format", "json"})
		if err != nil {
			return
		}
		var v struct {
			Version         string `json:"Version"`
			VulnerabilityDB struct {
				UpdatedAt string `json:"UpdatedAt"`
			} `json:"VulnerabilityDB"`
		}
		if json.Unmarshal(out, &v) != nil || v.Version == "" {
			return
		}
		p.val = fmt.Sprintf("trivy@%s;db@%s", v.Version, v.VulnerabilityDB.UpdatedAt)
	})
	return p.val
}

// sharedTrivyVersion is the process-wide probe used by all Trivy-backed scanners, so the
// version is resolved once per process regardless of how many Trivy scanners run.
var sharedTrivyVersion = newTrivyVersionProbe()

// trivyDBWarmer downloads Trivy's vulnerability database once (memoized) so that a run's
// concurrent scans don't each cold-start the DB. run is injectable for tests.
type trivyDBWarmer struct {
	once sync.Once
	err  error
	run  func(ctx context.Context, argv []string) ([]byte, error)
}

// warm runs `trivy image --download-db-only` at most once and returns any error (best-effort:
// callers treat failure as non-fatal, a real problem resurfaces at scan time).
func (w *trivyDBWarmer) warm(ctx context.Context) error {
	w.once.Do(func() {
		_, w.err = w.run(ctx, []string{"trivy", "image", "--download-db-only"})
	})
	return w.err
}

// sharedTrivyDB pre-warms the vuln DB once per process for all Trivy-backed scanners (they
// share Trivy's on-disk cache), so one download serves image, fs, and config scans.
var sharedTrivyDB = &trivyDBWarmer{run: execArgv}

// trivyChecksWarmer fetches Trivy's checks bundle once, before a run's concurrent config scans
// can each try to.
//
// The vuln database and the checks bundle are two different downloads into one cache directory,
// and warming the first does nothing for the second. A cold cache with several `trivy config`
// jobs in flight has them racing to populate it, and the ones that lose read a bundle that is
// still being written: `init Rego scanner: load checks`, which reads like a descriptor naming bad
// Rego and is not.
//
// Warmed by scanning an empty directory, because Trivy offers no download-only flag for this the
// way it does for the database. The scan finds nothing and costs a directory; what it is for is
// the fetch it does first.
type trivyChecksWarmer struct {
	once sync.Once
	err  error
	run  func(ctx context.Context, argv []string) ([]byte, error)
	// dir makes an empty directory to scan. Injectable so a test need not touch a filesystem.
	dir func() (string, func(), error)
}

// warm fetches the checks bundle at most once. Best-effort, like the database: a real problem
// resurfaces at scan time, and a warm that fails should not stop a scan that might still work.
func (w *trivyChecksWarmer) warm(ctx context.Context) error {
	w.once.Do(func() {
		dir, cleanup, err := w.dir()
		if err != nil {
			w.err = err
			return
		}
		defer cleanup()
		_, w.err = w.run(ctx, []string{"trivy", "config", "--quiet", dir})
	})
	return w.err
}

// emptyDir is a directory with nothing in it, and the way to remove it again.
func emptyDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "draugr-trivy-checks-")
	if err != nil {
		return "", func() {}, fmt.Errorf("warming trivy checks: %w", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// sharedTrivyChecks pre-warms the checks bundle once per process, for the one scanner that reads
// it.
var sharedTrivyChecks = &trivyChecksWarmer{run: execArgv, dir: emptyDir}
