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

	// A count, not a list. The rows carry the mark and say which findings rest on a tag, so
	// naming the references again answers a question already answered — and on a descriptor with
	// dozens of images it is a list nobody reads at the foot of the one they do.
	got := unpinnedCacheLine([]string{"alpine:3.19", "acme/api:latest"})
	if !strings.Contains(got, "2 images") {
		t.Errorf("want the scale, got: %s", got)
	}
	if strings.Contains(got, "alpine:3.19") {
		t.Errorf("the legend should not repeat what the rows already say: %s", got)
	}
	if !strings.Contains(got, "Pin a digest") {
		t.Errorf("the line should say what to do: %s", got)
	}
	// Scale-invariant: thirty reused entries is the same one line as two.
	many := make([]string, 30)
	for i := range many {
		many[i] = "img:1"
	}
	if len(unpinnedCacheLine(many)) > 100 {
		t.Errorf("the line grew with the number of images: %s", unpinnedCacheLine(many))
	}
	if one := unpinnedCacheLine([]string{"a:1"}); !strings.Contains(one, "1 image ") {
		t.Errorf("a single reuse should read as one: %s", one)
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
	// The caveat reaches the reader. Which entry it was is on the rows that carry the mark, and
	// on a run with no findings to mark it is in the JSON and in --evidence — repeating it here
	// costs every reader with dozens of images a list they do not read.
	if !strings.Contains(buf.String(), "from cache") {
		t.Errorf("the console never told the reader a result rested on a tag:\n%s", buf.String())
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

// TestWrapMessageKeepsURLsWhole covers the half of a failure a reader actually uses.
//
// A tool's error often ends in the URL it could not reach. Split at the margin it cannot be
// pasted anywhere, which is the only reason it is in the message. A long line is untidy; a
// severed URL is unusable.
func TestWrapMessageKeepsURLsWhole(t *testing.T) {
	const url = "https://cluster.example.com:443/apis/batch/v1/namespaces/default/jobs"
	got := wrapMessage("create job in \"default\": Post "+url+": getting credentials failed", 40)

	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, url) {
		t.Errorf("the URL was broken across lines and cannot be copied:\n%s", joined)
	}
	for _, line := range got {
		if strings.HasSuffix(line, "namesp") || strings.HasPrefix(line, "aces/") {
			t.Errorf("split mid-token: %q", line)
		}
	}
}

// TestWrapMessageElidesAtAWordBoundary: a fragment of a word reads as a different word, and a
// truncated identifier looks like a real one.
func TestWrapMessageElidesAtAWordBoundary(t *testing.T) {
	long := strings.Repeat("word ", 60) + "final"
	got := wrapMessage(long, 30)
	last := got[len(got)-1]
	if !strings.HasSuffix(last, "…") {
		t.Fatalf("the elided line should say it was cut: %q", last)
	}
	if strings.Contains(last, "wor…") {
		t.Errorf("cut mid-word: %q", last)
	}
}
