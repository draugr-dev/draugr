package cache

import (
	"os"
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
