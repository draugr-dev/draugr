package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// trivyVersionProbe derives a cache-version string for the Trivy-backed scanners that changes
// when the Trivy tool or its vulnerability database updates — so a DB refresh invalidates
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
// version can't be determined (Trivy absent or unexpected output) — callers then fall back to
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
// callers treat failure as non-fatal — a real problem resurfaces at scan time).
func (w *trivyDBWarmer) warm(ctx context.Context) error {
	w.once.Do(func() {
		_, w.err = w.run(ctx, []string{"trivy", "image", "--download-db-only"})
	})
	return w.err
}

// sharedTrivyDB pre-warms the vuln DB once per process for all Trivy-backed scanners (they
// share Trivy's on-disk cache), so one download serves image, fs, and config scans.
var sharedTrivyDB = &trivyDBWarmer{run: execArgv}
