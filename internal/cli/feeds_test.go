package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// cacheHome points feeds.Dir() at a temporary home and returns the cache directory.
func cacheHome(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	dir, err := feeds.Dir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

// seed writes a feed file and a manifest entry aged by the given duration.
func seed(t *testing.T, dir string, n feeds.Name, body string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(feeds.Path(dir, n), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m := map[feeds.Name]feeds.Record{}
	manifest := filepath.Join(dir, ".draugr-feeds.json")
	if data, err := os.ReadFile(manifest); err == nil { //nolint:gosec // under the test's temp dir
		_ = json.Unmarshal(data, &m)
	}
	m[n] = feeds.Record{
		URL:       feeds.URL(n),
		FetchedAt: time.Now().Add(-age),
		SHA256:    strings.Repeat("a", 64),
		Bytes:     int64(len(body)),
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// warnings captures the warnings emitted while fn runs.
func warnings(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

const kevJSON = `{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`

func TestResolveFeedPathPassesThrough(t *testing.T) {
	// Anything that is not a keyword is a path, used exactly as given. This is the air-gapped
	// route and it must not acquire a dependency on the cache existing.
	got, err := resolveFeed(context.Background(), feeds.KEV, "/etc/kev.json", "--kev", feeds.DefaultMaxAge)
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/etc/kev.json" {
		t.Errorf("got %q, want the path unchanged", got.path)
	}
}

func TestResolveFeedCache(t *testing.T) {
	dir := cacheHome(t)
	seed(t, dir, feeds.KEV, kevJSON, time.Hour)

	out := warnings(t, func() {
		got, err := resolveFeed(context.Background(), feeds.KEV, feedCache, "--kev", feeds.DefaultMaxAge)
		if err != nil {
			t.Fatal(err)
		}
		if got.path != feeds.Path(dir, feeds.KEV) {
			t.Errorf("got %q, want the cached copy", got.path)
		}
	})
	if out != "" {
		t.Errorf("a fresh cache warned about nothing: %s", out)
	}
}

func TestResolveFeedCacheEmpty(t *testing.T) {
	cacheHome(t)
	_, err := resolveFeed(context.Background(), feeds.KEV, feedCache, "--kev", feeds.DefaultMaxAge)
	if err == nil {
		t.Fatal("an empty cache resolved")
	}
	// The error has to say what to run. "cache is empty" alone leaves someone guessing at a
	// command they have never seen.
	if !strings.Contains(err.Error(), "draugr feeds update") {
		t.Errorf("error does not name the fix: %v", err)
	}
}

func TestResolveFeedCacheStaleWarnsAndProceeds(t *testing.T) {
	dir := cacheHome(t)
	seed(t, dir, feeds.EPSS, "cve,epss,percentile\n", 72*time.Hour)

	out := warnings(t, func() {
		got, err := resolveFeed(context.Background(), feeds.EPSS, feedCache, "--epss", feeds.DefaultMaxAge)
		if err != nil {
			t.Fatalf("a stale feed should be used, not refused: %v", err)
		}
		if got.path != feeds.Path(dir, feeds.EPSS) {
			t.Errorf("got %q, want the cached copy", got.path)
		}
	})
	if !strings.Contains(out, "stale exploitability feed") {
		t.Errorf("no staleness warning: %s", out)
	}
	if !strings.Contains(out, "3 days") {
		t.Errorf("the warning does not say how stale: %s", out)
	}
}

func TestResolveFeedOffline(t *testing.T) {
	dir := cacheHome(t)
	t.Setenv("DRAUGR_OFFLINE", "1")

	// Nothing cached: it must say so rather than attempt a fetch it has been told will fail.
	if _, err := resolveFeed(context.Background(), feeds.KEV, feedAuto, "--kev", feeds.DefaultMaxAge); err == nil {
		t.Error("offline with an empty cache resolved")
	} else if !strings.Contains(err.Error(), "DRAUGR_OFFLINE") {
		t.Errorf("error does not mention why it did not fetch: %v", err)
	}

	// Cached but stale: offline uses it, because the alternative is no answer at all.
	seed(t, dir, feeds.KEV, kevJSON, 100*time.Hour)
	out := warnings(t, func() {
		if _, err := resolveFeed(context.Background(), feeds.KEV, feedAuto, "--kev", feeds.DefaultMaxAge); err != nil {
			t.Errorf("offline with a stale cache: %v", err)
		}
	})
	if !strings.Contains(out, "stale") {
		t.Errorf("used a four-day-old feed without saying so: %s", out)
	}
}

func TestFeedNames(t *testing.T) {
	if got, err := feedNames(nil); err != nil || len(got) != 2 {
		t.Errorf("no arguments should mean every feed: %v %v", got, err)
	}
	if got, err := feedNames([]string{"KEV"}); err != nil || len(got) != 1 || got[0] != feeds.KEV {
		t.Errorf("case should not matter: %v %v", got, err)
	}
	if _, err := feedNames([]string{"nvd"}); err == nil {
		t.Error("an unknown feed was accepted")
	}
}

func TestFeedsStatus(t *testing.T) {
	dir := cacheHome(t)
	now := time.Now()

	var buf bytes.Buffer
	feedsStatus(&buf, dir, now)
	if !strings.Contains(buf.String(), "Nothing cached") {
		t.Errorf("an empty cache should say so plainly:\n%s", buf.String())
	}

	seed(t, dir, feeds.KEV, kevJSON, 2*time.Hour)
	buf.Reset()
	feedsStatus(&buf, dir, now)
	got := buf.String()
	if !strings.Contains(got, "2 hours") || !strings.Contains(got, "sha256:") {
		t.Errorf("missing age or digest:\n%s", got)
	}
	if !strings.Contains(got, "epss is not cached") {
		t.Errorf("should name the feed that is still missing:\n%s", got)
	}
	if strings.Contains(got, "stale") {
		t.Errorf("two hours is not stale:\n%s", got)
	}

	seed(t, dir, feeds.EPSS, "cve,epss\n", 50*time.Hour)
	buf.Reset()
	feedsStatus(&buf, dir, now)
	if got := buf.String(); !strings.Contains(got, "(stale)") {
		t.Errorf("a two-day-old feed is stale:\n%s", got)
	}
}

func TestHumanAgeAndBytes(t *testing.T) {
	ages := map[time.Duration]string{
		30 * time.Second:  "just now",
		20 * time.Minute:  "20 minutes",
		5 * time.Hour:     "5 hours",
		time.Hour:         "1 hour",
		119 * time.Minute: "2 hours",
		96 * time.Hour:    "4 days",
	}
	for d, want := range ages {
		if got := humanAge(d); got != want {
			t.Errorf("humanAge(%v) = %q, want %q", d, got, want)
		}
	}
	sizes := map[int64]string{512: "512 B", 2048: "2.0 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"}
	for n, want := range sizes {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestLoadExploitSourceFromCache(t *testing.T) {
	dir := cacheHome(t)
	seed(t, dir, feeds.KEV, kevJSON, time.Hour)
	seed(t, dir, feeds.EPSS, "cve,epss,percentile\nCVE-2021-44228,0.97,0.99\n", time.Hour)

	src, _, err := loadExploitSource(context.Background(), exploitability{
		kev: feedCache, epss: feedCache, threshold: 0.5, maxAge: feeds.DefaultMaxAge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if src == nil || src.Empty() {
		t.Fatal("no enrichment loaded from a populated cache")
	}
	// The whole point, end to end: a CVE on KEV comes out critical whatever it went in as.
	if got := src.Enrich(sarif.SeverityLow, "CVE-2021-44228"); got != sarif.SeverityCritical {
		t.Errorf("KEV escalation did not happen: got %q", got)
	}
}

func TestLoadExploitSourceDisabled(t *testing.T) {
	src, _, err := loadExploitSource(context.Background(), exploitability{})
	if err != nil || src != nil {
		t.Errorf("no flags should mean no enrichment: %v %v", src, err)
	}
}

func TestLoadExploitSourceBadFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	if _, _, err := loadExploitSource(context.Background(), exploitability{kev: missing, maxAge: feeds.DefaultMaxAge}); err == nil {
		t.Error("a missing --kev file was accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadExploitSource(context.Background(), exploitability{kev: bad, maxAge: feeds.DefaultMaxAge}); err == nil {
		t.Error("an unparseable --kev file was accepted")
	}
}

// stubFetch replaces the real fetch for the duration of a test, writing body into the cache
// and recording it, so the command can be exercised end to end without a network.
func stubFetch(t *testing.T, body string, err error) *int {
	t.Helper()
	calls := 0
	prev := fetchFeed
	t.Cleanup(func() { fetchFeed = prev })
	fetchFeed = func(_ context.Context, dir string, n feeds.Name, _ *http.Client) (feeds.Record, error) {
		calls++
		if err != nil {
			return feeds.Record{}, err
		}
		seed(t, dir, n, body, 0)
		return feeds.Load(dir)[n], nil
	}
	return &calls
}

func TestUpdateFeeds(t *testing.T) {
	dir := cacheHome(t)
	calls := stubFetch(t, kevJSON, nil)

	cmd := newFeedsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := updateFeeds(cmd, dir, feeds.Names(), false); err != nil {
		t.Fatal(err)
	}
	if *calls != 2 {
		t.Errorf("fetched %d feeds, want 2", *calls)
	}
	if got := buf.String(); !strings.Contains(got, "kev") || !strings.Contains(got, "epss") {
		t.Errorf("both feeds should be reported:\n%s", got)
	}

	// A second run leaves a current copy alone. Refetching 10 MiB because someone ran the
	// command twice is the behaviour that makes people stop running it.
	buf.Reset()
	before := *calls
	if err := updateFeeds(cmd, dir, feeds.Names(), false); err != nil {
		t.Fatal(err)
	}
	if *calls != before {
		t.Errorf("a current cache was refetched (%d extra calls)", *calls-before)
	}
	if !strings.Contains(buf.String(), "current") {
		t.Errorf("should say why it did nothing:\n%s", buf.String())
	}

	// --force overrides that.
	if err := updateFeeds(cmd, dir, feeds.Names(), true); err != nil {
		t.Fatal(err)
	}
	if *calls != before+2 {
		t.Errorf("--force did not refetch: %d calls, want %d", *calls, before+2)
	}
}

func TestUpdateFeedsStopsAtTheFirstFailure(t *testing.T) {
	dir := cacheHome(t)
	calls := stubFetch(t, "", errors.New("cisa is down"))

	cmd := newFeedsCommand()
	cmd.SetOut(io.Discard)
	err := updateFeeds(cmd, dir, feeds.Names(), false)
	if err == nil {
		t.Fatal("a failed fetch was reported as success")
	}
	if !strings.Contains(err.Error(), "cisa is down") {
		t.Errorf("the upstream error should survive: %v", err)
	}
	// One attempt, not two: a partial success the next scan cannot distinguish from a full one
	// is worse than a clean stop.
	if *calls != 1 {
		t.Errorf("kept going after a failure: %d calls", *calls)
	}
}

func TestResolveFeedAutoFetches(t *testing.T) {
	cacheHome(t)
	calls := stubFetch(t, kevJSON, nil)

	if _, err := resolveFeed(context.Background(), feeds.KEV, feedAuto, "--kev", feeds.DefaultMaxAge); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 {
		t.Errorf("auto with an empty cache should fetch: %d calls", *calls)
	}

	// Now it is fresh, so a second resolve must not reach out again.
	if _, err := resolveFeed(context.Background(), feeds.KEV, feedAuto, "--kev", feeds.DefaultMaxAge); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 {
		t.Errorf("auto refetched a fresh cache: %d calls", *calls)
	}
}

func TestResolveFeedAutoFallsBackToAStaleCache(t *testing.T) {
	dir := cacheHome(t)
	seed(t, dir, feeds.KEV, kevJSON, 96*time.Hour)
	stubFetch(t, "", errors.New("connection refused"))

	var got resolvedFeed
	out := warnings(t, func() {
		var err error
		got, err = resolveFeed(context.Background(), feeds.KEV, feedAuto, "--kev", feeds.DefaultMaxAge)
		if err != nil {
			t.Errorf("a feed outage should not fail a run with a usable copy on disk: %v", err)
		}
	})
	if got.path != feeds.Path(dir, feeds.KEV) {
		t.Errorf("got %q, want the cached copy", got.path)
	}
	// Both facts: the refresh failed, and what it fell back to is old.
	if !strings.Contains(out, "could not refresh") {
		t.Errorf("the outage was not reported:\n%s", out)
	}
	if !strings.Contains(out, "stale exploitability feed") {
		t.Errorf("the age of the fallback was not reported:\n%s", out)
	}
}

func TestResolveFeedAutoFailsWithNothingToFallBackOn(t *testing.T) {
	cacheHome(t)
	stubFetch(t, "", errors.New("connection refused"))

	_, err := resolveFeed(context.Background(), feeds.KEV, feedAuto, "--kev", feeds.DefaultMaxAge)
	if err == nil {
		t.Fatal("asked for enrichment, got none, and it passed")
	}
	if !strings.Contains(err.Error(), "draugr feeds update") {
		t.Errorf("error does not say how to recover: %v", err)
	}
}

func TestShort(t *testing.T) {
	if got := short(strings.Repeat("a", 64)); got != "sha256:"+strings.Repeat("a", 12) {
		t.Errorf("short digest = %q", got)
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("a short string should pass through: %q", got)
	}
}

func TestExploitSettingsDescriptorOnly(t *testing.T) {
	th := 0.1
	got := exploitSettings(scanOptions{epssThreshold: 0.5, setFlags: map[string]bool{}},
		&saga.ExploitabilityConfig{KEV: "cache", EPSS: "auto", EPSSThreshold: &th, MaxAge: "168h"})

	if got.kev != "cache" || got.epss != "auto" {
		t.Errorf("descriptor sources ignored: %+v", got)
	}
	if got.threshold != 0.1 {
		t.Errorf("threshold = %v, want the descriptor's 0.1 — the flag's default must not win", got.threshold)
	}
	if got.maxAge != 168*time.Hour {
		t.Errorf("maxAge = %v, want 168h", got.maxAge)
	}
	// The error a reader gets should name the thing they would edit.
	if got.kevFrom != "config.exploitability.kev" {
		t.Errorf("kevFrom = %q", got.kevFrom)
	}
}

func TestExploitSettingsFlagsOverride(t *testing.T) {
	th := 0.1
	cfg := &saga.ExploitabilityConfig{KEV: "cache", EPSS: "cache", EPSSThreshold: &th}
	opts := scanOptions{
		kevFile: "/tmp/kev.json", epssThreshold: 0.9,
		setFlags: map[string]bool{"kev": true, "epss-threshold": true},
	}
	got := exploitSettings(opts, cfg)

	if got.kev != "/tmp/kev.json" || got.kevFrom != "--kev" {
		t.Errorf("--kev did not win: %+v", got)
	}
	if got.threshold != 0.9 {
		t.Errorf("threshold = %v, want the flag's 0.9", got.threshold)
	}
	// --epss was not typed, so the descriptor still supplies it.
	if got.epss != "cache" || got.epssFrom != "config.exploitability.epss" {
		t.Errorf("an untyped flag should not clear the descriptor: %+v", got)
	}
}

func TestExploitSettingsThresholdTypedAtItsDefault(t *testing.T) {
	// --epss-threshold 0.5 is the default *value*, and passing it deliberately must still beat
	// a descriptor that says otherwise. This is why resolution reads which flags were typed
	// rather than comparing against defaults.
	th := 0.1
	got := exploitSettings(
		scanOptions{epssThreshold: 0.5, setFlags: map[string]bool{"epss-threshold": true}},
		&saga.ExploitabilityConfig{EPSS: "cache", EPSSThreshold: &th})
	if got.threshold != 0.5 {
		t.Errorf("threshold = %v, want 0.5 — an explicit flag at its default value still wins", got.threshold)
	}
}

func TestExploitSettingsNoFlagProvenance(t *testing.T) {
	// A programmatic caller has no flag information, so a nil setFlags cannot mean "the caller
	// set nothing" — its values have to be honoured rather than silently dropped.
	got := exploitSettings(scanOptions{kevFile: "/tmp/kev.json", epssThreshold: 0.3}, nil)
	if got.kev != "/tmp/kev.json" || got.threshold != 0.3 {
		t.Errorf("programmatic options were dropped: %+v", got)
	}
	if got.maxAge != feeds.DefaultMaxAge {
		t.Errorf("maxAge = %v, want the default", got.maxAge)
	}
}

func TestExploitSettingsOffByDefault(t *testing.T) {
	got := exploitSettings(scanOptions{epssThreshold: 0.5, setFlags: map[string]bool{}}, nil)
	if got.kev != "" || got.epss != "" {
		t.Errorf("enrichment should be off with neither a flag nor a descriptor: %+v", got)
	}
}

func TestResolveFeedHonoursConfiguredMaxAge(t *testing.T) {
	dir := cacheHome(t)
	seed(t, dir, feeds.KEV, kevJSON, 72*time.Hour)

	// Three days old, and a descriptor that says a week is fine: not stale, nothing said.
	out := warnings(t, func() {
		if _, err := resolveFeed(context.Background(), feeds.KEV, feedCache, "--kev", 168*time.Hour); err != nil {
			t.Fatal(err)
		}
	})
	if out != "" {
		t.Errorf("warned despite a maxAge that covers it: %s", out)
	}
}

func TestLoadExploitSourceReportsProvenance(t *testing.T) {
	dir := cacheHome(t)
	seed(t, dir, feeds.KEV, kevJSON, time.Hour)
	seed(t, dir, feeds.EPSS, "cve,epss,percentile\nCVE-2021-44228,0.97,0.99\n", 96*time.Hour)

	src, prov, err := loadExploitSource(context.Background(), exploitability{
		kev: feedCache, epss: feedCache, threshold: 0.5, maxAge: feeds.DefaultMaxAge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(prov) != 2 {
		t.Fatalf("got %d feeds of provenance, want 2: %+v", len(prov), prov)
	}
	for _, p := range prov {
		if p.FetchedAt.IsZero() || p.SHA256 == "" || p.URL == "" {
			t.Errorf("%s: incomplete provenance %+v", p.Name, p)
		}
	}
	// Four days old against a 24-hour bar. The report has to carry that, not just the log of
	// the run that produced it.
	if prov[0].Stale {
		t.Error("the one-hour-old feed was marked stale")
	}
	if !prov[1].Stale {
		t.Error("the four-day-old feed was not marked stale in the provenance")
	}

	// And the date reaches the escalation, which is what makes the claim checkable.
	_, esc := src.Explain(sarif.SeverityLow, "CVE-2021-44228")
	if esc == nil || esc.AsOf == "" {
		t.Errorf("escalation cannot cite a date: %+v", esc)
	}
}

func TestLoadExploitSourceProvenanceForAFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(path, []byte(kevJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	_, prov, err := loadExploitSource(context.Background(),
		exploitability{kev: path, kevFrom: "--kev", maxAge: feeds.DefaultMaxAge})
	if err != nil {
		t.Fatal(err)
	}
	if len(prov) != 1 {
		t.Fatalf("provenance = %+v", prov)
	}
	// A file has no fetch to describe. Reporting a zero time is the honest answer; inventing
	// one would put a date on the report that nothing supports.
	if !prov[0].FetchedAt.IsZero() || prov[0].URL != "" || prov[0].Stale {
		t.Errorf("a supplied file claimed a provenance it does not have: %+v", prov[0])
	}
}
