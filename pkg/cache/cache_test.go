package cache

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	stored, err := os.ReadFile(filepath.Join(dir, "k.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(stored, gzipMagic) {
		t.Fatal("entry was not compressed")
	}
	raw, err := json.Marshal(entry{Report: sarif.Report{Tool: "trivy", Results: results}})
	if err != nil {
		t.Fatal(err)
	}
	if ratio := float64(len(raw)) / float64(len(stored)); ratio < 3 {
		t.Errorf("compression ratio %.1fx — expected SARIF to squash much harder", ratio)
	}

	got, ok := c.Get("k")
	if !ok || len(got.Results) != len(results) {
		t.Fatalf("round trip lost data: ok=%v n=%d", ok, len(got.Results))
	}
}

func TestLocalReadsUncompressedEntries(t *testing.T) {
	// A cache written by an older Draugr is plain JSON. Refusing it would silently discard a warm
	// cache on upgrade — a full re-scan for a change that alters no answer.
	dir := t.TempDir()
	data, err := json.Marshal(entry{
		Report:   sarif.Report{Tool: "trivy", Results: []sarif.Result{{RuleID: "CVE-1"}}},
		StoredAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, ok := NewLocal(dir, 0).Get("old")
	if !ok {
		t.Fatal("a pre-compression entry was discarded")
	}
	if len(got.Results) != 1 || got.Results[0].RuleID != "CVE-1" {
		t.Errorf("read back %+v", got.Results)
	}
}

func TestLocalIgnoresCorruptEntries(t *testing.T) {
	dir := t.TempDir()
	// Truncated gzip, and gzip-looking bytes that are not.
	for name, body := range map[string][]byte{
		"a": append(append([]byte{}, gzipMagic...), 0x08, 0x00, 0x99),
		"b": []byte("{not json"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := NewLocal(dir, 0).Get(name); ok {
			t.Errorf("%s: corrupt entry was served as a result", name)
		}
	}
}
