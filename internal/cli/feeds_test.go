package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/pkg/saga"
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

const kevJSON = `{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`

func TestFeedNames(t *testing.T) {
	if got, err := feedNames(nil); err != nil || len(got) != len(feeds.Names()) {
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
	if !strings.Contains(got, "epss and govulndb are not cached. Run `draugr feeds update epss govulndb`") {
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

	// A stale Go database is refused by a scan rather than read, and the status says so instead
	// of promising the report will merely be marked stale.
	seed(t, dir, feeds.GoVulnDB, "", 50*time.Hour)
	buf.Reset()
	feedsStatus(&buf, dir, now)
	got = buf.String()
	if !strings.Contains(got, "govulndb older than") || !strings.Contains(got, "A scan does not read it") {
		t.Errorf("a stale Go database should be named as unread:\n%s", got)
	}
	if strings.Contains(got, "govulndb older than 1 day. A scan uses it") || strings.Contains(got, "and govulndb older") {
		t.Errorf("the Go database was given the exploitability feeds' consequence:\n%s", got)
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
	if *calls != len(feeds.Names()) {
		t.Errorf("fetched %d feeds, want %d", *calls, len(feeds.Names()))
	}
	if got := buf.String(); !strings.Contains(got, "kev") || !strings.Contains(got, "epss") {
		t.Errorf("both feeds should be reported:\n%s", got)
	}

	// A second run leaves a current copy alone. Refetching 10 MiB because someone ran the
	// command twice is the behavior that makes people stop running it.
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
	if *calls != before+len(feeds.Names()) {
		t.Errorf("--force did not refetch: %d calls, want %d", *calls, before+len(feeds.Names()))
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

	if got.KEV != "cache" || got.EPSS != "auto" {
		t.Errorf("descriptor sources ignored: %+v", got)
	}
	if got.Threshold != 0.1 {
		t.Errorf("threshold = %v, want the descriptor's 0.1, the flag's default must not win", got.Threshold)
	}
	if got.MaxAge != 168*time.Hour {
		t.Errorf("maxAge = %v, want 168h", got.MaxAge)
	}
	// The error a reader gets should name the thing they would edit.
	if got.KEVFrom != "config.exploitability.kev" {
		t.Errorf("kevFrom = %q", got.KEVFrom)
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

	if got.KEV != "/tmp/kev.json" || got.KEVFrom != "--kev" {
		t.Errorf("--kev did not win: %+v", got)
	}
	if got.Threshold != 0.9 {
		t.Errorf("threshold = %v, want the flag's 0.9", got.Threshold)
	}
	// --epss was not typed, so the descriptor still supplies it.
	if got.EPSS != "cache" || got.EPSSFrom != "config.exploitability.epss" {
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
	if got.Threshold != 0.5 {
		t.Errorf("threshold = %v, want 0.5, an explicit flag at its default value still wins", got.Threshold)
	}
}

func TestExploitSettingsNoFlagProvenance(t *testing.T) {
	// A programmatic caller has no flag information, so a nil setFlags cannot mean "the caller set
	// nothing". Its values have to be honored rather than silently dropped.
	got := exploitSettings(scanOptions{kevFile: "/tmp/kev.json", epssThreshold: 0.3}, nil)
	if got.KEV != "/tmp/kev.json" || got.Threshold != 0.3 {
		t.Errorf("programmatic options were dropped: %+v", got)
	}
	if got.MaxAge != feeds.DefaultMaxAge {
		t.Errorf("maxAge = %v, want the default", got.MaxAge)
	}
}

func TestExploitSettingsOffByDefault(t *testing.T) {
	got := exploitSettings(scanOptions{epssThreshold: 0.5, setFlags: map[string]bool{}}, nil)
	if got.KEV != "" || got.EPSS != "" {
		t.Errorf("enrichment should be off with neither a flag nor a descriptor: %+v", got)
	}
}

// A fetch that fails with a copy already on disk must not fail the run.
//
// This step exists so a scan cannot rank everything as though nothing were exploited. A cached
// catalog does not do that. It ranks on data of a known age, and the report says how old. So
// blocking a pipeline on somebody else's outage buys nothing when the answer is already here,
// which is what a release blocked on a 403 from CISA costs.
func TestUpdateFeedsKeepsTheCachedCopyWhenAFetchFails(t *testing.T) {
	dir := cacheHome(t)
	// Stale, so the fetch is attempted rather than skipped as current.
	for _, n := range feeds.Names() {
		seed(t, dir, n, kevJSON, 30*24*time.Hour)
	}
	stubFetch(t, "", errors.New("unexpected status 403 Forbidden"))

	cmd := newFeedsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := updateFeeds(cmd, dir, feeds.Names(), false); err != nil {
		t.Fatalf("a cached copy should survive a failed fetch: %v", err)
	}
	got := buf.String()
	// Both feeds, because stopping at the first would leave the second unattempted for a reason
	// that no longer stops anything.
	for _, n := range feeds.Names() {
		if !strings.Contains(got, string(n)) {
			t.Errorf("%s was not reported:\n%s", n, got)
		}
	}
	// The age is the point: a reader has to be able to tell how old the ranking now is.
	if !strings.Contains(got, "kept the cached copy") || !strings.Contains(got, "403") {
		t.Errorf("should say what it kept and why:\n%s", got)
	}
	// And the file is still there to be scanned with.
	if len(feeds.Load(dir)) != len(feeds.Names()) {
		t.Errorf("a failed fetch removed the cache: %v", feeds.Load(dir))
	}
}

// With nothing cached there is no answer to keep, and a scan would rank everything as though
// nothing were exploited. That is the case the hard failure exists for, and it stays.
func TestUpdateFeedsStillFailsWithAnEmptyCache(t *testing.T) {
	dir := cacheHome(t)
	stubFetch(t, "", errors.New("unexpected status 403 Forbidden"))

	cmd := newFeedsCommand()
	cmd.SetOut(io.Discard)
	if err := updateFeeds(cmd, dir, feeds.Names(), false); err == nil {
		t.Fatal("a failed fetch with no cache was reported as success")
	}
}

// Whichever source won has to name itself. A threshold in a report without its source is a line
// somebody drew that nobody can attribute. And the answer decides whether a band a reader
// disputes is a policy or an accident.
func TestExploitSettingsThresholdNamesWhatSetIt(t *testing.T) {
	th := 0.1
	for _, tc := range []struct {
		name string
		opts scanOptions
		cfg  *saga.ExploitabilityConfig
		want string
	}{
		{
			"nothing set it",
			scanOptions{epssThreshold: 0.5, setFlags: map[string]bool{}},
			&saga.ExploitabilityConfig{EPSS: "cache"},
			"the default",
		},
		{
			"the descriptor set it",
			scanOptions{epssThreshold: 0.5, setFlags: map[string]bool{}},
			&saga.ExploitabilityConfig{EPSS: "cache", EPSSThreshold: &th},
			"config.exploitability.epssThreshold",
		},
		{
			"the flag set it, over a descriptor that also did",
			scanOptions{epssThreshold: 0.9, setFlags: map[string]bool{"epss-threshold": true}},
			&saga.ExploitabilityConfig{EPSS: "cache", EPSSThreshold: &th},
			"--epss-threshold",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exploitSettings(tc.opts, tc.cfg); got.ThresholdFrom != tc.want {
				t.Errorf("thresholdFrom = %q, want %q", got.ThresholdFrom, tc.want)
			}
		})
	}
}
