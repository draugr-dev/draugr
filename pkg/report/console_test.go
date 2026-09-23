package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
	"github.com/draugr-dev/draugr/pkg/tui"
)

func TestUnpinnedCacheLine(t *testing.T) {
	if got := unpinnedCacheLine(nil); got != "" {
		t.Errorf("nothing reused from a tag-keyed entry should print nothing, got %q", got)
	}

	// A count, not a list. The rows carry the mark and say which findings rest on a tag, so naming
	// the references again answers a question already answered, and on a descriptor with dozens of
	// images it is a list nobody reads at the foot of the one they do.
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
		Release: saga.Release{Version: "1.0.0"},
		Run: engine.Result{
			Stats: engine.Stats{Jobs: 1, CacheHits: 1, UnpinnedCacheHits: []string{"alpine:3.19"}},
		},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	// The caveat reaches the reader. Which entry it was is on the rows that carry the mark, and on a
	// run with no findings to mark it is in the JSON and in --evidence. Repeating it here costs every
	// reader with dozens of images a list they do not read.
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
			want: "17 jobs in 18.2s · 11s waiting for the trivy cache",
		},
		{
			name: "waiting, alongside a saving",
			st: engine.Stats{Jobs: 17, Duration: 18200 * time.Millisecond, CacheHits: 4,
				ToolWaits: map[string]time.Duration{"trivy": 11 * time.Second}},
			want: "17 jobs in 18.2s · 4 from cache · 11s waiting for the trivy cache",
		},
		{
			// Too short to perceive, so it explains nothing and only competes with the findings.
			name: "a wait too short to be a reason",
			st: engine.Stats{Jobs: 2, Duration: time.Second,
				ToolWaits: map[string]time.Duration{"trivy": 200 * time.Millisecond}},
			want: "2 jobs in 1s",
		},
		{
			name: "two tools are named in a stable order",
			st: engine.Stats{Jobs: 9, Duration: 30 * time.Second,
				ToolWaits: map[string]time.Duration{"trivy": 8 * time.Second, "grype": 3 * time.Second}},
			want: "9 jobs in 30s · 3s waiting for the grype cache, 8s waiting for the trivy cache",
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

// TestGateOffIsSaidInTheDefaultView is the strongest case in the file: --no-gate exits 0 on a
// verdict of FAIL, so anything reading the exit code is told the opposite of what the report says.
func TestGateOffIsSaidInTheDefaultView(t *testing.T) {
	d := Data{
		Release: saga.Release{Version: "1.0.0"},
		Gate:    GateSettings{Threshold: "high", Disabled: true},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "--no-gate") {
		t.Errorf("a disabled gate was not mentioned:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "exit code") {
		t.Errorf("the line should say what a disabled gate changes:\n%s", buf.String())
	}
}

// TestADefaultGateSaysNothingUntilAsked. A verdict under the default gate is the ordinary case,
// and a line restating it on every scan is one more thing between a reader and the findings.
func TestADefaultGateSaysNothingUntilAsked(t *testing.T) {
	// Nothing named is the default gate, which is the priority band. A reader who configured
	// nothing already has it, so stating it on every run spends a line on news nobody needs.
	d := Data{
		Release: saga.Release{Version: "1.0.0"},
		Gate:    GateSettings{},
	}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Gate:") {
		t.Errorf("the default gate should not announce itself:\n%s", buf.String())
	}

	d.Evidence = true
	buf.Reset()
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	// Including the default, because "the default" is an answer only when the report gives it.
	// The word "gate" is the label on its own column now, so the fact beside it is the rule.
	if !strings.Contains(buf.String(), "gate") || !strings.Contains(buf.String(), "fails on P1") {
		t.Errorf("--evidence should state the gate whatever it is:\n%s", buf.String())
	}
}

// TestALoosenedGateIsSaidWithoutAsking covers the case a reader cannot otherwise see: a pass under
// a narrowed gate looks exactly like a pass under a full one.
func TestALoosenedGateIsSaidWithoutAsking(t *testing.T) {
	for _, c := range []struct {
		name string
		gate GateSettings
		want string
	}{
		{
			name: "a threshold looser than the default",
			gate: GateSettings{Threshold: "critical"},
			want: "fails on critical",
		},
		{
			name: "one control let off",
			gate: GateSettings{Threshold: "high", PerControl: map[string]sarif.Severity{"licenses": "critical"}},
			want: "licenses fails on critical severity",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := (consoleReporter{}).Render(&buf, Data{
				Release: saga.Release{Version: "1.0.0"}, Gate: c.gate,
			}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), c.want) {
				t.Errorf("want %q in:\n%s", c.want, buf.String())
			}
		})
	}
}

// TestAStricterGateNeedsNoAnnouncement. It can only fail more than a reader expects, and the
// failure says so itself. Unlike a loosening, which produces a pass that looks like any other.
func TestAGateSomebodyChoseSaysSo(t *testing.T) {
	// A severity gate is not a stricter version of the default, it is the other question: it
	// judges what a scanner called the flaw rather than the band it lands in here. Which of the
	// two catches more depends on the component, so neither can be announced as the looser and
	// both have to be stated, because a pass means something different under each.
	for _, tc := range []struct {
		name string
		gate GateSettings
		want string
	}{
		{"a severity gate", GateSettings{Threshold: "low"}, "fails on low severity"},
		{
			"a per-control threshold",
			GateSettings{Threshold: "high", PerControl: map[string]sarif.Severity{"secrets": "low"}},
			"secrets fails on low severity",
		},
		{"a band other than the default", GateSettings{FailOnPriority: "P3"}, "fails on P3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := (consoleReporter{}).Render(&buf, Data{
				Release: saga.Release{Version: "1.0.0"}, Gate: tc.gate,
			}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("want %q in the default view:\n%s", tc.want, buf.String())
			}
		})
	}
}

// TestTheGateLineStatesOneQuestion: a line that could say both leaves a reader with two candidates
// for why their build is red, which is the thing the one-gate rule exists to remove.
func TestTheGateLineStatesOneQuestion(t *testing.T) {
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, Data{
		Release:  saga.Release{Version: "1.0.0"},
		Gate:     GateSettings{Threshold: "high"},
		Evidence: true,
	}); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.Contains(line, "fails on high severity") {
		t.Errorf("the severity gate does not say it is one:\n%s", line)
	}
	if strings.Contains(line, "P1") {
		t.Errorf("a severity gate mentioned a priority band:\n%s", line)
	}
}

// TestGateOverridesAreNamedAndOrdered: which control was exempted is the content of the exemption,
// and a map's iteration order would make two runs of one scan differ.
func TestGateOverridesAreNamedAndOrdered(t *testing.T) {
	g := GateSettings{Threshold: "high", PerControl: map[string]sarif.Severity{
		"licenses": "critical", "iac": "critical", "sca": "critical",
	}}
	want := "iac fails on critical severity · licenses fails on critical severity · sca fails on critical severity"
	for range 5 {
		if got := gateOverrides(g); got != want {
			t.Fatalf("gateOverrides = %q, want %q", got, want)
		}
	}
}

// Twelve results reused is a different statement an hour old and a day old, and the count alone
// does not distinguish them.
func TestTimingLineSaysHowOldTheOldestReusedEntryWas(t *testing.T) {
	for _, tc := range []struct {
		name string
		age  time.Duration
		want string
	}{
		{"hours are rounded to hours", 19*time.Hour + 3*time.Minute + 12*time.Second, "oldest 19h0m0s"},
		{"under an hour, to minutes", 42*time.Minute + 30*time.Second, "oldest 43m0s"},
		{"no age recorded, nothing claimed", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := engine.Stats{Jobs: 4, CacheHits: 3, Duration: time.Second, OldestCacheAge: tc.age}
			got := runLine(st)
			if tc.want == "" {
				if strings.Contains(got, "oldest") {
					t.Errorf("age claimed with none recorded: %s", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("runLine = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

// The descriptor section names every file and where it came from.
//
// A fragment pulled from another repository is a file this checkout does not contain, which is the
// one thing a reader cannot work out from a path, and the version it was pinned at is how somebody
// refers to a shared policy. The resolved commit is what makes the run reproducible after the tag
// has moved, so both are said.
func TestTheDescriptorSectionSaysWhereEachFileCameFrom(t *testing.T) {
	for _, c := range []struct {
		name string
		src  skald.DescriptorSource
		want []string
		not  []string
	}{
		{
			name: "the root file",
			src:  skald.DescriptorSource{Path: "draugr.saga.yaml", Root: true, Digest: "sha256:abc123def4567"},
			want: []string{"root", "abc123def456"},
		},
		{
			name: "a fragment beside it",
			src:  skald.DescriptorSource{Path: "security/x.saga-fragment.yaml", Digest: "sha256:0123456789abc"},
			want: []string{"0123456789ab"},
			not:  []string{"root"},
		},
		{
			name: "a fragment from another repository",
			src: skald.DescriptorSource{
				Path: "platform/shared.saga-fragment.yaml", Digest: "sha256:ffffffffffffff",
				URL: "https://github.com/acme/platform", Revision: "v2.4.0", Resolved: "d6a7fb0a3f4b9c",
			},
			// The host is kept, unlike a repository row: which repository a policy came from is
			// the fact, and a run may read fragments from several.
			want: []string{"github.com/acme/platform@v2.4.0", "d6a7fb0a3f4b"},
			// The file's own digest would be a second hex string beside the commit that already
			// pins the tree it came out of.
			not: []string{"ffffffffffff", "https://"},
		},
		{
			name: "a fragment pinned by commit, where the revision is the resolution",
			src: skald.DescriptorSource{
				Path: "p/x.saga-fragment.yaml",
				URL:  "https://github.com/acme/platform", Revision: "d6a7fb0a3f4b9c", Resolved: "d6a7fb0a3f4b9c",
			},
			want: []string{"github.com/acme/platform@d6a7fb0a3f4b9c"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := descriptorSourceNote(c.src)
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("note = %q, want it to carry %q", got, w)
				}
			}
			for _, n := range c.not {
				if strings.Contains(got, n) {
					t.Errorf("note = %q, should not carry %q", got, n)
				}
			}
		})
	}
}

// A descriptor that is one file gets no section: the row above already named it.
func TestOneFileDescriptorGetsNoSection(t *testing.T) {
	var b bytes.Buffer
	d := Data{Descriptor: &skald.DescriptorRef{
		Sources: []skald.DescriptorSource{{Path: "draugr.saga.yaml", Root: true}},
	}}
	writeDescriptorSources(&b, tui.For(&b), d, true)
	if b.Len() != 0 {
		t.Errorf("a single-file descriptor printed a section:\n%s", b.String())
	}
	// And nothing is printed without --evidence, whatever it holds.
	d.Descriptor.Sources = append(d.Descriptor.Sources, skald.DescriptorSource{Path: "a.yaml"})
	b.Reset()
	writeDescriptorSources(&b, tui.For(&b), d, false)
	if b.Len() != 0 {
		t.Errorf("the section printed without --evidence:\n%s", b.String())
	}
}
