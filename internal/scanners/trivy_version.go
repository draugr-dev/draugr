package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// trivyVersionProbe derives a cache-version string for the Trivy-backed scanners that changes
// when the Trivy tool or its vulnerability database updates, so a DB refresh invalidates
// cached results instead of waiting out the TTL. The probe runs `trivy version --format json`
// once (memoized), and again after the run refreshes the database (reprobe); run is injectable for
// tests.
type trivyVersionProbe struct {
	once sync.Once
	mu   sync.RWMutex
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
	p.once.Do(func() { p.set(p.probe(ctx)) })
	return p.get()
}

// reprobe asks Trivy again once its database has been refreshed, so the version names the database
// the run reads. The first answer is taken before the refresh, because the refresh's own command
// line depends on the tool's version, and its db@ date is then the copy the refresh replaced. An
// answer that cannot be read keeps the one before it.
func (p *trivyVersionProbe) reprobe(ctx context.Context) {
	p.cacheVersion(ctx)
	if v := p.probe(ctx); v != "" {
		p.set(v)
	}
}

// probe runs `trivy version --format json` and returns its cache version, or "" when it cannot.
func (p *trivyVersionProbe) probe(ctx context.Context) string {
	out, err := p.run(ctx, []string{"trivy", "version", "--format", "json"})
	if err != nil {
		return ""
	}
	var v struct {
		Version         string `json:"Version"`
		VulnerabilityDB struct {
			UpdatedAt string `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	if json.Unmarshal(out, &v) != nil || v.Version == "" {
		return ""
	}
	return fmt.Sprintf("trivy@%s;db@%s", v.Version, v.VulnerabilityDB.UpdatedAt)
}

func (p *trivyVersionProbe) get() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.val
}

func (p *trivyVersionProbe) set(v string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.val = v
}

// showsSuppressed reports whether the Trivy that will run is new enough to list what it excluded.
//
// Read from the memoized probe rather than asking again: the cache key is built before the command
// line is, so by the time this is called the version has been resolved for this process. An
// unresolved version answers no, which runs the command Draugr has always run. A flag an older
// Trivy does not have would fail the scan outright, and losing a suppression record is the lesser
// of the two.
func (p *trivyVersionProbe) showsSuppressed() bool {
	return trivyAtLeast(p.get(), showSuppressedSince)
}

// showSuppressedSince is the first Trivy carrying `--show-suppressed` and the findings it reports.
const showSuppressedSince = "0.53.0"

// skipsNotices reports whether the Trivy that will run has `--skip-version-check` and
// `--disable-telemetry`. Read from the memoized probe for the reason showsSuppressed gives.
func (p *trivyVersionProbe) skipsNotices() bool {
	return trivyAtLeast(p.get(), noticeFlagsSince)
}

// noticeFlagsSince is the first Trivy carrying `--skip-version-check` and `--disable-telemetry`,
// and the first to send the request they turn off: both flags and the request arrived together in
// 0.63.0. An older Trivy sends nothing and refuses either flag.
const noticeFlagsSince = "0.63.0"

// trivyAtLeast compares the probe's `trivy@X.Y.Z;db@...` against a floor, field by field.
//
// Its own comparison rather than a semver dependency: three integers, and the answer where any of
// them cannot be read is no, which keeps the command as it was.
func trivyAtLeast(probed, floor string) bool {
	probed = strings.TrimPrefix(probed, "trivy@")
	if i := strings.IndexByte(probed, ';'); i >= 0 {
		probed = probed[:i]
	}
	got, want := strings.Split(probed, "."), strings.Split(floor, ".")
	if len(got) < len(want) {
		return false
	}
	for i := range want {
		a, err := strconv.Atoi(strings.TrimSpace(got[i]))
		if err != nil {
			return false
		}
		b, _ := strconv.Atoi(want[i])
		if a != b {
			return a > b
		}
	}
	return true
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
	// version resolves the shared probe before the command line is built, because a warm runs
	// ahead of every scan and so ahead of the cache key that otherwise resolves it first. Nil
	// leaves the probe as it is.
	version func(ctx context.Context) string
	// refreshed reads the version again after a download, so its db@ date is the database the run
	// reads rather than the one the download replaced. Nil leaves the probe as it is.
	refreshed func(ctx context.Context)
}

// warm runs `trivy image --download-db-only` at most once and returns any error (best-effort:
// callers treat failure as non-fatal, a real problem resurfaces at scan time).
func (w *trivyDBWarmer) warm(ctx context.Context) error {
	w.once.Do(func() {
		resolveTrivyVersion(ctx, w.version)
		argv := append([]string{"trivy", "image", "--download-db-only"}, trivyNoticeArgs()...)
		if _, w.err = w.run(ctx, argv); w.err == nil && w.refreshed != nil {
			w.refreshed(ctx)
		}
	})
	return w.err
}

// resolveTrivyVersion runs version, when there is one, so trivyNoticeArgs answers for the Trivy
// that will run rather than for one not yet asked.
func resolveTrivyVersion(ctx context.Context, version func(context.Context) string) {
	if version != nil {
		version(ctx)
	}
}

// sharedTrivyDB pre-warms the vuln DB once per process for all Trivy-backed scanners (they
// share Trivy's on-disk cache), so one download serves image, fs, and config scans.
var sharedTrivyDB = &trivyDBWarmer{
	run: execArgv, version: sharedTrivyVersion.cacheVersion, refreshed: sharedTrivyVersion.reprobe,
}

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
	// version resolves the shared probe first, as trivyDBWarmer's does.
	version func(ctx context.Context) string
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
		resolveTrivyVersion(ctx, w.version)
		argv := append(append([]string{"trivy", "config", "--quiet"}, trivyNoticeArgs()...), dir)
		_, w.err = w.run(ctx, argv)
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
var sharedTrivyChecks = &trivyChecksWarmer{run: execArgv, dir: emptyDir, version: sharedTrivyVersion.cacheVersion}
