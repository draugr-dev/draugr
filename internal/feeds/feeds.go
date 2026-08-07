// Package feeds fetches and caches the exploitability datasets Draugr can enrich findings
// with: CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS scores.
//
// Fetching is never implicit. A scan that silently reaches the internet is not reproducible,
// and the gate has to be — so the network is touched when someone asks for it, by running
// `draugr feeds update` or by passing `auto`, and a scan otherwise reads a local cache with no
// network access at all. That keeps the air-gapped path and the connected path the same code.
//
// The cache records where each feed came from and when, because "we escalated this to critical
// because it was on KEV as of 2026-08-01" is an auditable statement and "KEV said so" is not.
package feeds

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Name identifies a feed.
type Name string

// The feeds Draugr knows how to fetch.
const (
	KEV  Name = "kev"
	EPSS Name = "epss"
)

// Names lists every known feed, in the order commands should present them.
func Names() []Name { return []Name{KEV, EPSS} }

// maxFeedBytes caps a download. EPSS is the larger of the two at roughly 250k rows; 256 MiB is
// far above anything either feed has been, and bounded is the point — an unbounded read of a
// URL is a memory-exhaustion bug waiting for a bad day upstream.
const maxFeedBytes = 256 << 20

// DefaultMaxAge is how old a cached feed may be before `auto` refetches it and a scan warns.
//
// One day, because EPSS is republished daily: a score is a 30-day probability recomputed every
// morning, so a week-old copy silently mis-ranks. KEV changes far less often and is held to the
// same bar deliberately — two staleness rules to explain is worse than one that is slightly
// strict for one feed.
const DefaultMaxAge = 24 * time.Hour

// source describes where a feed comes from and how to decode it.
type source struct {
	url        string
	file       string // the cache filename, after any decompression
	gzipped    bool
	describe   string
	publisher  string
	licenseURL string
}

// sources is the pinned upstream for each feed. Both are published at stable URLs by their
// respective owners, over HTTPS with certificate verification — which is the integrity story
// for data that has no signature to check.
var sources = map[Name]source{
	KEV: {
		url:        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		file:       "kev.json",
		describe:   "CISA Known Exploited Vulnerabilities catalog",
		publisher:  "CISA",
		licenseURL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	},
	EPSS: {
		url:        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
		file:       "epss.csv",
		gzipped:    true,
		describe:   "FIRST EPSS scores",
		publisher:  "FIRST",
		licenseURL: "https://www.first.org/epss/",
	},
}

// Describe returns a human-readable name for a feed, or "" if it is not a known one.
func Describe(n Name) string { return sources[n].describe }

// URL returns the upstream a feed is fetched from, or "" if it is not a known one.
func URL(n Name) string { return sources[n].url }

// Record is what the cache knows about one fetched feed.
type Record struct {
	URL       string    `json:"url"`
	FetchedAt time.Time `json:"fetchedAt"`
	SHA256    string    `json:"sha256"` // of the decompressed bytes on disk
	Bytes     int64     `json:"bytes"`
}

// Age reports how long ago the feed was fetched, as of now.
func (r Record) Age(now time.Time) time.Duration { return now.Sub(r.FetchedAt) }

// Stale reports whether the feed is older than maxAge. A maxAge of zero or less means never
// stale — the caller has said it does not care, which is a legitimate thing to say on a runner
// that is deliberately pinned to a known copy.
func (r Record) Stale(now time.Time, maxAge time.Duration) bool {
	return maxAge > 0 && r.Age(now) > maxAge
}

// manifestName records what has been fetched, alongside the feeds themselves.
const manifestName = ".draugr-feeds.json"

// Dir is the feed cache, ~/.draugr/feeds.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".draugr", "feeds"), nil
}

// Path is where a feed's data lives inside dir, decompressed and ready to parse.
func Path(dir string, n Name) string { return filepath.Join(dir, sources[n].file) }

// Load reads the manifest. A missing or unreadable manifest is an empty one: the feeds it
// described are then treated as absent, which is the safe direction — worst case a refetch.
func Load(dir string) map[Name]Record {
	out := map[Name]Record{}
	data, err := os.ReadFile(filepath.Join(dir, manifestName)) // #nosec G304 -- path is ours
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out)
	// A manifest entry whose file has since been deleted describes nothing. Drop it, so
	// "cached" and "on disk" cannot disagree.
	for n := range out {
		if _, err := os.Stat(Path(dir, n)); err != nil {
			delete(out, n)
		}
	}
	return out
}

// Fetch downloads one feed into dir, decompressing it if the upstream is gzipped, and records
// what it fetched. It returns the resulting cache entry.
//
// The write is atomic: a temporary file in the same directory, renamed into place. A fetch
// interrupted halfway must not leave a half a catalogue behind for the next scan to parse as
// though it were complete.
func Fetch(ctx context.Context, dir string, n Name, client *http.Client) (Record, error) {
	src, ok := sources[n]
	if !ok {
		return Record{}, fmt.Errorf("unknown feed %q; known feeds are %s", n, list(Names()))
	}
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Minute}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Record{}, fmt.Errorf("create feed cache: %w", err)
	}

	data, err := get(ctx, client, src.url)
	if err != nil {
		return Record{}, fmt.Errorf("fetch %s: %w", src.describe, err)
	}
	if src.gzipped {
		if data, err = gunzip(data); err != nil {
			return Record{}, fmt.Errorf("decompress %s: %w", src.describe, err)
		}
	}

	dest := Path(dir, n)
	if err := writeAtomic(dest, data); err != nil {
		return Record{}, fmt.Errorf("write %s: %w", dest, err)
	}

	sum := sha256.Sum256(data)
	rec := Record{
		URL:       src.url,
		FetchedAt: time.Now().UTC(),
		SHA256:    hex.EncodeToString(sum[:]),
		Bytes:     int64(len(data)),
	}
	if err := record(dir, n, rec); err != nil {
		return rec, fmt.Errorf("record the fetch: %w", err)
	}
	return rec, nil
}

// get retrieves a URL, refusing anything but 200 and reading at most maxFeedBytes.
func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // pinned feed URL
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
}

// gunzip decompresses a gzip stream, bounded like the download it came from — a compressed
// feed can expand to far more than it weighed on the wire.
func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	return io.ReadAll(io.LimitReader(zr, maxFeedBytes))
}

// writeAtomic writes data to path via a temporary file in the same directory.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".draugr-feed-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once the rename has succeeded
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// record merges one entry into the manifest.
func record(dir string, n Name, rec Record) error {
	m := Load(dir)
	m[n] = rec
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, manifestName), data, 0o600)
}

// list renders feed names for an error message.
func list(names []Name) string {
	s := make([]string, len(names))
	for i, n := range names {
		s[i] = string(n)
	}
	sort.Strings(s)
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
