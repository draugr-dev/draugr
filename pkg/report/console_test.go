package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

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

// TestRunLineReportsWaitingOnce covers the whole point of moving the retry chatter to debug: a
// scan that took three times as long still has to say why, and the answer is the total.
func TestRunLineReportsWaitingOnce(t *testing.T) {
	for _, c := range []struct {
		name, want string
		st         engine.Stats
	}{
		{
			name: "waiting, with nothing else to report",
			st: engine.Stats{Jobs: 17, Duration: 18200 * time.Millisecond,
				ToolWaits: map[string]time.Duration{"trivy": 11 * time.Second}},
			want: "Ran 17 jobs in 18.2s — 11s waiting for the trivy cache.",
		},
		{
			name: "waiting, alongside a saving",
			st: engine.Stats{Jobs: 17, Duration: 18200 * time.Millisecond, CacheHits: 4,
				ToolWaits: map[string]time.Duration{"trivy": 11 * time.Second}},
			want: "Ran 17 jobs in 18.2s — 4 from cache, 11s waiting for the trivy cache.",
		},
		{
			// Too short to perceive, so it explains nothing and only competes with the findings.
			name: "a wait too short to be a reason",
			st: engine.Stats{Jobs: 2, Duration: time.Second,
				ToolWaits: map[string]time.Duration{"trivy": 200 * time.Millisecond}},
			want: "Ran 2 jobs in 1s.",
		},
		{
			name: "two tools are named in a stable order",
			st: engine.Stats{Jobs: 9, Duration: 30 * time.Second,
				ToolWaits: map[string]time.Duration{"trivy": 8 * time.Second, "grype": 3 * time.Second}},
			want: "Ran 9 jobs in 30s — 3s waiting for the grype cache, 8s waiting for the trivy cache.",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := runLine(c.st); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}
