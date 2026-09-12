package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// "Fix first" describes a shortlist. Over the whole set it stops being a recommendation and
// becomes a label, and the reader loses what the default view was telling them.
func TestFixFirstHeading(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		s            summary
		shown, total int
		want         string
	}{
		{"a shortlist says so", summary{}, 10, 437, "FIX FIRST  top 10 of 437, by priority"},
		{"the whole set is not a shortlist", summary{}, 437, 437, "FIX FIRST  all 437, by priority"},
		{"one finding is not a list", summary{}, 1, 1, "THE FINDING  by priority"},
		{"filtered and capped", summary{minPriority: "p2"}, 10, 50,
			"FIX FIRST  top 10 of 50, by priority, P2 and above"},
		{"filtered, hiding some", summary{minPriority: "p1", hidden: 12}, 3, 3,
			"FIX FIRST  all 3, by priority, P1 and above; 12 lower-priority finding(s) hidden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := fixFirstHeading(tui.Plain(), tc.s, tc.shown, tc.total); got != tc.want {
				t.Errorf("heading = %q,\n    want %q", got, tc.want)
			}
		})
	}
}

// One component repeats the same value on every row and answers a question nobody has. The
// column earns its width only when it tells findings apart.
func TestComponentColumnOnlyWhenItDistinguishes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		fs   []finding
		want bool
	}{
		{"no components", []finding{{}, {}}, false},
		{"one component", []finding{{component: "web"}, {component: "web"}}, false},
		{"two components", []finding{{component: "web"}, {component: "api"}}, true},
		{"one named, one not", []finding{{component: "web"}, {}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := manyComponents(tc.fs); got != tc.want {
				t.Errorf("manyComponents = %v, want %v", got, tc.want)
			}
		})
	}
}

// The engine has recorded this since caching was added and nothing showed it, which left
// `--cache-dir` unverifiable at a terminal: the run is faster, and whether the cache did it is a
// question the output did not answer.
func TestRunLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		stats engine.Stats
		want  string
	}{
		{
			name:  "a run with no jobs describes nothing",
			stats: engine.Stats{Duration: time.Second},
		},
		{
			// A duration of zero means the run never finished, not that it was instant.
			name:  "an unfinished run describes nothing",
			stats: engine.Stats{Jobs: 4},
		},
		{
			name:  "jobs and wall-clock",
			stats: engine.Stats{Jobs: 4, Duration: 2500 * time.Millisecond},
			want:  "Ran 4 jobs in 2.5s.",
		},
		{
			name:  "one job reads as one",
			stats: engine.Stats{Jobs: 1, Duration: 247 * time.Millisecond},
			want:  "Ran 1 job in 247ms.",
		},
		{
			name:  "cache hits are the answer to whether the cache worked",
			stats: engine.Stats{Jobs: 11, CacheHits: 4, Duration: 3 * time.Second},
			want:  "Ran 11 jobs in 3s · 4 from cache.",
		},
		{
			// Two components sharing a repository plan two jobs and one scan answers both. Without
			// a name for it, a reader counting jobs against scans finds a discrepancy and no cause.
			name:  "a shared scan is a different saving from a cache hit",
			stats: engine.Stats{Jobs: 16, Deduped: 5, Duration: 4951 * time.Millisecond},
			want:  "Ran 16 jobs in 4.951s · 5 shared with an identical job.",
		},
		{
			name:  "both savings",
			stats: engine.Stats{Jobs: 11, CacheHits: 4, Deduped: 1, Duration: 34500 * time.Millisecond},
			want:  "Ran 11 jobs in 34.5s · 4 from cache, 1 shared with an identical job.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := runLine(tc.stats); got != tc.want {
				t.Errorf("runLine = %q, want %q", got, tc.want)
			}
		})
	}
}

// A location links to the line it names, at the revision that was read. A link to a branch shows
// whatever is there now, which is the same path, a different file, and a line number landing
// somewhere unrelated. A link that is silently wrong is worse than no link.
func TestALocationLinksToTheRevisionThatWasRead(t *testing.T) {
	t.Parallel()

	const rev = "925cb20fa1e2f905a88f7883eecfa756daa8be2c"
	links := blobLinks(Data{Repositories: []RepositoryProvenance{
		{URL: "https://github.com/acme/payments-api", Revision: rev},
		{URL: "https://gitlab.com/acme/infra.git", Revision: rev},
		// Read from the checkout on disk, so the files are in nobody's commit.
		{URL: "https://github.com/acme/wip", Revision: rev, WorkingTree: true},
		// Nothing to pin it to.
		{URL: "https://github.com/acme/unknown"},
		// A host that may serve nothing over the web, and a shape that is not the one both forges
		// agree on.
		{URL: "git@github.com:acme/ssh.git", Revision: rev},
		{URL: "https://git.internal.example/acme/forge", Revision: rev},
		{URL: ".", Revision: rev},
	}})

	for _, tc := range []struct {
		name string
		f    finding
		want string
	}{
		{"github, with a line", finding{repository: "https://github.com/acme/payments-api", location: "requirements.txt:1"},
			"https://github.com/acme/payments-api/blob/" + rev + "/requirements.txt#L1"},
		{"gitlab, and the .git goes", finding{repository: "https://gitlab.com/acme/infra.git", location: "main.tf"},
			"https://gitlab.com/acme/infra/blob/" + rev + "/main.tf"},
		{"a working tree is not a commit", finding{repository: "https://github.com/acme/wip", location: "a.py:3"}, ""},
		{"no revision, nowhere honest to point", finding{repository: "https://github.com/acme/unknown", location: "a.py:3"}, ""},
		{"ssh names a host that may serve nothing", finding{repository: "git@github.com:acme/ssh.git", location: "a.py:3"}, ""},
		{"a forge whose shape we do not know", finding{repository: "https://git.internal.example/acme/forge", location: "a.py:3"}, ""},
		{"a local path is not a URL", finding{repository: ".", location: "a.py:3"}, ""},
		{"a finding with no location", finding{repository: "https://github.com/acme/payments-api"}, ""},
		{"a finding from nowhere we scanned", finding{repository: "https://github.com/other/repo", location: "a.py:3"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := links.forFinding(tc.f); got != tc.want {
				t.Errorf("forFinding = %q,\n          want %q", got, tc.want)
			}
		})
	}
}

// What a descriptor declares and no enabled control examines, as a table: every line answers the
// same two questions, and a reader comparing them should not have to find the answer in a
// different place on every row.
func TestUncoveredSurfacesAreATable(t *testing.T) {
	t.Parallel()

	var b bytes.Buffer
	writeUncovered(&b, tui.Plain(), Data{Uncovered: []Gap{
		{Component: "api", Surface: "hosts", Controls: []string{"dast", "headers", "tls"}},
		{Component: "api", Surface: "images", Controls: []string{"images"}},
	}})
	out := b.String()
	for _, want := range []string{
		"NOT CHECKED",
		"api hosts   3 controls off: dast, headers, tls",
		"api images  1 control off: images",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// Nothing declared that nothing looks at, so no block and no heading.
	var empty bytes.Buffer
	writeUncovered(&empty, tui.Plain(), Data{})
	if empty.Len() != 0 {
		t.Errorf("a fully covered descriptor should print nothing:\n%s", empty.String())
	}
}

// A mark is two words. A two-word line between two rows that are one line each reads as a row that
// broke rather than one that is long, so the sentence beside it gives way instead.
func TestAMarkNeverTakesALineOfItsOwn(t *testing.T) {
	t.Parallel()

	const long = "Possible disclosure of permanent session cookie due to missing Vary: Cookie header when a proxy is in front"
	got := notesFor(tui.Plain(), finding{
		message:    long,
		escalation: &sarif.Escalation{Signal: "epss", Detail: "EPSS 0.87"},
	})
	if len(got) != 1 {
		t.Fatalf("got %d lines, want the mark and the sentence on one:\n%q", len(got), got)
	}
	if !strings.HasPrefix(got[0], "↑ EPSS 0.87 · Possible disclosure") {
		t.Errorf("line = %q", got[0])
	}
	if n := len([]rune(got[0])); n > messageWidth {
		t.Errorf("line is %d, past the %d every sentence here is held to: %q", n, messageWidth, got[0])
	}
	if !strings.HasSuffix(got[0], "…") {
		t.Errorf("a sentence cut to fit should say so: %q", got[0])
	}

	// Where several things argued about one finding there is no room left to cut the sentence to,
	// and a fragment somebody cannot place is worth less than a line.
	crowded := notesFor(tui.Plain(), finding{
		message:       long,
		escalation:    &sarif.Escalation{Signal: "epss", Detail: "EPSS 0.87"},
		priorityFloor: "secrets are ranked P1 wherever they are found, whatever the component is",
	})
	if len(crowded) != 3 {
		t.Fatalf("got %d lines, want one per statement:\n%q", len(crowded), crowded)
	}
	if !strings.HasPrefix(crowded[2], "Possible disclosure") {
		t.Errorf("the sentence should be whole on its own line: %q", crowded[2])
	}
}
