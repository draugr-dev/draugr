package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestUnpinnedCacheLine(t *testing.T) {
	if got := unpinnedCacheLine(nil); got != "" {
		t.Errorf("nothing reused from a tag-keyed entry should print nothing, got %q", got)
	}
	got := unpinnedCacheLine([]string{"alpine:3.19", "acme/api:latest"})
	for _, want := range []string{"alpine:3.19", "acme/api:latest", "--cache-require-digest", "Pin a digest"} {
		if !strings.Contains(got, want) {
			t.Errorf("the line should mention %q, got: %s", want, got)
		}
	}
}

// TestUnpinnedCacheLineStaysReadable keeps a caveat from becoming a wall. A fleet scan can reuse
// dozens of tag-keyed entries, and a line naming all of them is one nobody finishes reading.
func TestUnpinnedCacheLineStaysReadable(t *testing.T) {
	got := unpinnedCacheLine([]string{"a:1", "b:1", "c:1", "d:1", "e:1"})
	if !strings.Contains(got, "and 2 more") {
		t.Errorf("want the tail summarised, got: %s", got)
	}
	if strings.Contains(got, "d:1") || strings.Contains(got, "e:1") {
		t.Errorf("only the first three should be named, got: %s", got)
	}
}

// TestConsoleSaysWhenAResultCameFromATagKeyedEntry checks the line reaches the report rather than
// only that the function can build it.
func TestConsoleSaysWhenAResultCameFromATagKeyedEntry(t *testing.T) {
	d := Data{
		Release: saga.Release{Name: "app", Version: "1.0.0"},
		Run: engine.Result{
			Stats: engine.Stats{Jobs: 1, CacheHits: 1, UnpinnedCacheHits: []string{"alpine:3.19"}},
		},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "alpine:3.19") {
		t.Errorf("the console never told the reader which result rested on a tag:\n%s", buf.String())
	}
}
