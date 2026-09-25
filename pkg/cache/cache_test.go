package cache

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

func sampleReport() sarif.Report {
	return sarif.Report{Tool: "t", Results: []sarif.Result{{RuleID: "R", Level: sarif.LevelWarning}}}
}

func TestNoop(t *testing.T) {
	var c Cache = Noop{}
	if err := c.Put("k", sampleReport()); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("k"); ok {
		t.Error("noop should always miss")
	}
}

func TestMemory(t *testing.T) {
	c := NewMemory()
	if _, ok := c.Get("k"); ok {
		t.Error("empty cache should miss")
	}
	if err := c.Put("k", sampleReport()); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("k")
	if !ok || len(got.Results) != 1 {
		t.Fatalf("expected hit with 1 result, got ok=%v report=%+v", ok, got)
	}
}

func TestLocalRoundTrip(t *testing.T) {
	c := NewLocal(t.TempDir(), 0) // no expiry
	if _, ok := c.Get("missing"); ok {
		t.Error("missing key should miss")
	}
	if err := c.Put("k", sampleReport()); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("k")
	if !ok || got.Tool != "t" {
		t.Fatalf("expected hit, got ok=%v report=%+v", ok, got)
	}
}

func TestLocalTTLExpiry(t *testing.T) {
	c := NewLocal(t.TempDir(), time.Hour)
	base := time.Now()
	c.now = func() time.Time { return base }
	if err := c.Put("k", sampleReport()); err != nil {
		t.Fatal(err)
	}
	// Within TTL → hit.
	if _, ok := c.Get("k"); !ok {
		t.Error("entry within TTL should hit")
	}
	// Advance beyond TTL → miss.
	c.now = func() time.Time { return base.Add(2 * time.Hour) }
	if _, ok := c.Get("k"); ok {
		t.Error("entry past TTL should miss")
	}
}

func TestLocalCorruptData(t *testing.T) {
	dir := t.TempDir()
	c := NewLocal(dir, 0)
	// Write junk at the expected path.
	if err := os.WriteFile(c.pathFor("bad"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("bad"); ok {
		t.Error("corrupt entry should miss")
	}
}

func TestLocalCompressesEntries(t *testing.T) {
	dir := t.TempDir()
	c := NewLocal(dir, 0)

	// A realistic entry: SARIF is repetitive, which is the whole reason compressing it pays.
	var results []sarif.Result
	for i := range 400 {
		results = append(results, sarif.Result{
			Tool: "trivy", RuleID: fmt.Sprintf("CVE-2026-%04d", i), Level: sarif.LevelError,
			Message:  "a package is affected by a known vulnerability with a long, repetitive description",
			Location: sarif.Location{URI: "app/requirements.txt", StartLine: i},
		})
	}
	if err := c.Put("k", sarif.Report{Tool: "trivy", Results: results}); err != nil {
		t.Fatal(err)
	}

	//nolint:gosec // a path under the test's own temp dir
	stored, err := os.ReadFile(filepath.Join(dir, "k"+entrySuffix))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(stored, []byte{0x1f, 0x8b}) {
		t.Fatal("entry was not compressed")
	}
	raw, err := json.Marshal(entry{Report: sarif.Report{Tool: "trivy", Results: results}})
	if err != nil {
		t.Fatal(err)
	}
	if ratio := float64(len(raw)) / float64(len(stored)); ratio < 3 {
		t.Errorf("compression ratio %.1fx, expected SARIF to squash much harder", ratio)
	}

	got, ok := c.Get("k")
	if !ok || len(got.Results) != len(results) {
		t.Fatalf("round trip lost data: ok=%v n=%d", ok, len(got.Results))
	}
}

// TestLocalLeavesNoEntryUnderTheOldName covers the rename.
//
// Entries were called `.json` when they were plain JSON and kept the name when compression
// landed, so the extension described bytes that were not there. Renaming costs one cold cache,
// which is what a cache is for; what it must not cost is a file that is never read again and
// never removed, because nothing evicts anything. Expiry only makes a read miss.
func TestLocalLeavesNoEntryUnderTheOldName(t *testing.T) {
	dir := t.TempDir()
	data, err := json.Marshal(entry{
		Report:   sarif.Report{Tool: "trivy", Results: []sarif.Result{{RuleID: "CVE-1"}}},
		StoredAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "old"+legacySuffix)
	if err := os.WriteFile(legacy, data, 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewLocal(dir, 0)
	// Not read: the name no longer describes an entry, and serving one would mean guessing at
	// the encoding from the bytes rather than knowing it from the name.
	if _, ok := c.Get("old"); ok {
		t.Error("an entry under the pre-compression name was served")
	}
	// And writing that key clears it, rather than leaving it to sit there forever.
	if err := c.Put("old", sarif.Report{Tool: "trivy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("the superseded entry is still on disk (%v), so the directory only grows", err)
	}
	if _, ok := c.Get("old"); !ok {
		t.Error("the newly written entry should read back")
	}
}

func TestLocalIgnoresCorruptEntries(t *testing.T) {
	dir := t.TempDir()
	// Truncated gzip, and gzip-looking bytes that are not.
	for name, body := range map[string][]byte{
		"a": {0x1f, 0x8b, 0x08, 0x00, 0x99},
		"b": []byte("{not json"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name+entrySuffix), body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := NewLocal(dir, 0).Get(name); ok {
			t.Errorf("%s: corrupt entry was served as a result", name)
		}
	}
}

func TestReadOnlyServesButDoesNotStore(t *testing.T) {
	dir := t.TempDir()
	writable := NewLocal(dir, 0)
	if err := writable.Put("known", sarif.Report{Tool: "trivy"}); err != nil {
		t.Fatal(err)
	}

	ro := ReadOnly(NewLocal(dir, 0))
	// Reading stays useful: entries already there were written by runs that were trusted.
	if _, ok := ro.Get("known"); !ok {
		t.Error("a read-only cache should still serve what is there")
	}
	// Writing is discarded silently. A read-only cache is a configuration, not an error, and a
	// scan failing because it could not write a cache would be absurd.
	if err := ro.Put("new", sarif.Report{Tool: "trivy"}); err != nil {
		t.Errorf("Put returned an error: %v", err)
	}
	if _, ok := NewLocal(dir, 0).Get("new"); ok {
		t.Error("a read-only cache wrote an entry")
	}
}

// A report that has to explain a reused finding needs to say where the cache was and how long it
// keeps things, and the cache is the only thing that knows.
func TestLocalDescribesItself(t *testing.T) {
	dir := t.TempDir()
	got := NewLocal(dir, 24*time.Hour).Describe()
	if got.Dir != dir || got.TTL != 24*time.Hour || got.ReadOnly {
		t.Errorf("Describe() = %+v", got)
	}
}

// Read-only is a property of the wrapper, not of the cache underneath, so it has to be added to
// whatever the wrapped one says rather than replacing it.
func TestReadOnlyDescribesTheCacheItWraps(t *testing.T) {
	dir := t.TempDir()
	got := ReadOnly(NewLocal(dir, time.Hour)).(Describer).Describe()
	if got.Dir != dir || got.TTL != time.Hour {
		t.Errorf("the wrapped cache's description was lost: %+v", got)
	}
	if !got.ReadOnly {
		t.Error("a read-only view described itself as writable")
	}
}

// The age of a reused entry is the difference between trusting it and re-running, and Get throws
// it away.
func TestGetStampedReturnsWhenTheEntryWasWritten(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 31, 4, 11, 2, 0, time.UTC)
	c := NewLocal(dir, 0)
	c.now = func() time.Time { return at }
	if err := c.Put("k", sarif.Report{}); err != nil {
		t.Fatal(err)
	}
	_, storedAt, ok := c.GetStamped("k")
	if !ok {
		t.Fatal("miss on an entry just written")
	}
	if !storedAt.Equal(at) {
		t.Errorf("storedAt = %v, want %v", storedAt, at)
	}
	if _, _, ok := c.GetStamped("absent"); ok {
		t.Error("a miss reported a hit")
	}
}

// Expiry is decided the same way whichever accessor asked, or a stamped read would serve entries
// a plain one refuses.
func TestGetStampedHonorsTheTTL(t *testing.T) {
	c := NewLocal(t.TempDir(), time.Hour)
	c.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	if err := c.Put("k", sarif.Report{}); err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC) }
	if _, _, ok := c.GetStamped("k"); ok {
		t.Error("an expired entry was served")
	}
}

// A cache that cannot say when it wrote something still answers what it holds.
func TestReadOnlyFallsBackWhenTheWrappedCacheCannotStamp(t *testing.T) {
	m := NewMemory()
	if err := m.Put("k", sarif.Report{}); err != nil {
		t.Fatal(err)
	}
	_, storedAt, ok := ReadOnly(m).(StampedGetter).GetStamped("k")
	if !ok {
		t.Fatal("the entry was lost on the way through the wrapper")
	}
	if !storedAt.IsZero() {
		t.Errorf("a time was invented for a cache that does not record one: %v", storedAt)
	}
}

func TestLocalStoresAnyKeyAsOneFileInItsDirectory(t *testing.T) {
	dir := t.TempDir()
	c := NewLocal(dir, 0)
	scoped := strings.Repeat("a", 64) + "@services/api=" + strings.Repeat("b", 40) + ";.gitleaks.toml=" + strings.Repeat("c", 40)
	for _, key := range []string{
		strings.Repeat("a", 64) + "@" + strings.Repeat("d", 40),
		scoped,
		scoped + ";services/web=" + strings.Repeat("e", 40),
		strings.Repeat("a", 64) + "@" + strings.Repeat("services/part=0123456789abcdef;", 12),
		"../outside",
	} {
		if err := c.Put(key, sampleReport()); err != nil {
			t.Fatalf("Put(%q): %v", key, err)
		}
		if _, ok := c.Get(key); !ok {
			t.Errorf("Get(%q) missed after Put", key)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Errorf("the directory holds %d entries, want one file per key", len(entries))
	}
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) > 255 {
			t.Errorf("entry %q is a directory or longer than a file name may be", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "outside"+entrySuffix)); err == nil {
		t.Error("a key holding .. was written outside the cache directory")
	}
	plain := strings.Repeat("a", 64) + "@" + strings.Repeat("d", 40)
	if _, err := os.Stat(filepath.Join(dir, plain+entrySuffix)); err != nil {
		t.Errorf("a plain key is not stored under its own name, so existing entries go unread: %v", err)
	}
}

func TestLocalPutReportsAnUnwritableDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewLocal(file, 0).Put("k", sampleReport()); err == nil {
		t.Error("Put into a path that is a file returned no error")
	}
	if err := NewLocal(filepath.Join(file, "sub"), 0).Put("k", sampleReport()); err == nil {
		t.Error("Put under a path that is a file returned no error")
	}
}
