package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/feeds"
)

// seedFeed writes a feed's data and its manifest entry, fetched age ago as of now.
func seedFeed(t *testing.T, dir string, n feeds.Name, now time.Time, age time.Duration) {
	t.Helper()
	path := feeds.Path(dir, n)
	if n == feeds.GoVulnDB {
		// The Go database is cached as an extracted directory tree.
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := map[feeds.Name]feeds.Record{}
	manifest := filepath.Join(dir, ".draugr-feeds.json")
	if data, err := os.ReadFile(manifest); err == nil { //nolint:gosec // under the test's temp dir
		_ = json.Unmarshal(data, &m)
	}
	m[n] = feeds.Record{URL: feeds.URL(n), FetchedAt: now.Add(-age), SHA256: strings.Repeat("a", 64), Bytes: 2048}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func feedByName(t *testing.T, out FeedsStatusOutput, n feeds.Name) FeedStatus {
	t.Helper()
	for _, f := range out.Feeds {
		if f.Name == string(n) {
			return f
		}
	}
	t.Fatalf("no entry for %s in %+v", n, out.Feeds)
	return FeedStatus{}
}

// An empty cache is an answer, and the answer names every feed and the one command that fetches
// them all.
func TestFeedsStatusEmptyCache(t *testing.T) {
	dir := t.TempDir()
	out := FeedsStatus(dir, time.Now())

	if len(out.Feeds) != len(feeds.Names()) {
		t.Fatalf("got %d feeds, want one entry per known feed: %+v", len(out.Feeds), out.Feeds)
	}
	for _, f := range out.Feeds {
		if f.Cached || f.Stale || f.FetchedAt != "" || f.SHA256 != "" {
			t.Errorf("%s: nothing is cached, got %+v", f.Name, f)
		}
		if f.Source == "" || f.Description == "" || f.IfStale == "" {
			t.Errorf("%s: source, description and ifStale are stated for a missing feed too: %+v", f.Name, f)
		}
	}
	if len(out.Missing) != len(feeds.Names()) || len(out.Stale) != 0 {
		t.Errorf("missing = %v, stale = %v", out.Missing, out.Stale)
	}
	if out.Next != "draugr feeds update" {
		t.Errorf("next = %q, want the bare command that fetches every feed", out.Next)
	}
	if !strings.Contains(out.Note, "give it to the user") {
		t.Errorf("note should hand the fetch to the user: %q", out.Note)
	}
	if out.Dir != dir || out.MaxAge != "24 hours" {
		t.Errorf("dir = %q, maxAge = %q", out.Dir, out.MaxAge)
	}
}

// Each state reported apart, and the next step naming exactly the feeds that need it.
func TestFeedsStatusFreshStaleAndMissing(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	seedFeed(t, dir, feeds.KEV, now, time.Hour)
	seedFeed(t, dir, feeds.GoVulnDB, now, 72*time.Hour)

	out := FeedsStatus(dir, now)

	kev := feedByName(t, out, feeds.KEV)
	if !kev.Cached || kev.Stale {
		t.Errorf("kev is an hour old: %+v", kev)
	}
	if kev.FetchedAt != "2026-09-25T11:00:00Z" || kev.Age != "1 hour" || kev.AgeSeconds != 3600 {
		t.Errorf("kev fetchedAt/age = %q, %q, %d", kev.FetchedAt, kev.Age, kev.AgeSeconds)
	}
	if kev.Bytes != 2048 || kev.Size != "2.0 KiB" || kev.SHA256 != strings.Repeat("a", 64) {
		t.Errorf("kev size/digest = %d, %q, %q", kev.Bytes, kev.Size, kev.SHA256)
	}
	if kev.Source != feeds.URL(feeds.KEV) {
		t.Errorf("kev source = %q", kev.Source)
	}

	govuln := feedByName(t, out, feeds.GoVulnDB)
	if !govuln.Cached || !govuln.Stale || govuln.Age != "3 days" {
		t.Errorf("govulndb is three days old: %+v", govuln)
	}
	if epss := feedByName(t, out, feeds.EPSS); epss.Cached {
		t.Errorf("epss was never fetched: %+v", epss)
	}

	if !slices.Equal(out.Missing, []string{"epss"}) || !slices.Equal(out.Stale, []string{"govulndb"}) {
		t.Errorf("missing = %v, stale = %v", out.Missing, out.Stale)
	}
	// In the order feeds are presented, whichever state put each one there.
	if out.Next != "draugr feeds update epss govulndb" {
		t.Errorf("next = %q", out.Next)
	}
}

// Nothing to do is said as nothing to do: no command, so a caller has nothing to relay.
func TestFeedsStatusAllCurrent(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for _, n := range feeds.Names() {
		seedFeed(t, dir, n, now, 30*time.Minute)
	}
	out := FeedsStatus(dir, now)
	if out.Next != "" || len(out.Missing) != 0 || len(out.Stale) != 0 {
		t.Errorf("everything is current, got next=%q missing=%v stale=%v", out.Next, out.Missing, out.Stale)
	}
	if out.Note != "Every feed is cached and current." {
		t.Errorf("note = %q", out.Note)
	}
}

// A stale exploitability feed is still read and a stale Go database is not, so one sentence for
// both would be wrong for one of them.
func TestFeedsStatusStatesEachFeedsConsequence(t *testing.T) {
	out := FeedsStatus(t.TempDir(), time.Now())
	for _, n := range []feeds.Name{feeds.KEV, feeds.EPSS} {
		if got := feedByName(t, out, n).IfStale; !strings.Contains(got, "ranks findings on old data") {
			t.Errorf("%s ifStale = %q", n, got)
		}
	}
	got := feedByName(t, out, feeds.GoVulnDB).IfStale
	if !strings.Contains(got, "does not read") || !strings.Contains(got, "vuln.go.dev") ||
		!strings.Contains(got, "--offline") {
		t.Errorf("govulndb ifStale = %q", got)
	}
}

// Driven through a client, as an assistant would call it, against a cache the test owns.
func TestFeedsStatusToolOverMCP(t *testing.T) {
	dir := t.TempDir()
	orig := feedsDir
	feedsDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { feedsDir = orig })
	seedFeed(t, dir, feeds.EPSS, time.Now(), 2*time.Hour)

	sess := connect(t, Options{Registry: builtins.Registry(), Root: t.TempDir()})
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "feeds_status"})
	if err != nil || res.IsError {
		t.Fatalf("feeds_status: %v %+v", err, res)
	}
	var out FeedsStatusOutput
	decode(t, res, &out)
	if out.Dir != dir {
		t.Errorf("dir = %q, want the injected cache %q", out.Dir, dir)
	}
	if out.Next != "draugr feeds update kev govulndb" {
		t.Errorf("next = %q", out.Next)
	}
}

func TestFeedsStatusToolReportsAnUnlocatableCache(t *testing.T) {
	orig := feedsDir
	feedsDir = func() (string, error) { return "", errors.New("no home") }
	t.Cleanup(func() { feedsDir = orig })
	if _, _, err := FeedsStatusTool(context.Background(), nil, EmptyInput{}); err == nil {
		t.Error("want the cache-location error returned")
	}
}
