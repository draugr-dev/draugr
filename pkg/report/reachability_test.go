package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func blockFor(as ...engine.AnalyzerReachability) ([]string, []string) {
	var total engine.ReachabilitySummary
	total.Analyzers = as
	for _, a := range as {
		total.Reachable += a.Reachable
		total.Unreachable += a.Unreachable
		total.Unknown += a.Unknown
	}
	return reachabilityBlock(Data{Run: engine.Result{Reachability: total}})
}

func TestReachabilityBlockKeepsAnalyzersApart(t *testing.T) {
	// Two analyzers cover different ecosystems and reach their answers by different methods.
	// Summed into one figure they would read as a single verdict of uniform strength.
	rows, _ := blockFor(
		engine.AnalyzerReachability{Analyzer: "dep-scan", Reachable: 1, Unreachable: 12, Unknown: 3},
		engine.AnalyzerReachability{Analyzer: "govulncheck", Reachable: 2, Unreachable: 6},
	)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want one per analyzer: %v", len(rows), rows)
	}
	if !strings.HasPrefix(rows[0], "dep-scan") || !strings.HasPrefix(rows[1], "govulncheck") {
		t.Errorf("rows not one per analyzer in name order: %v", rows)
	}
	if !strings.Contains(rows[0], "3 undetermined") {
		t.Errorf("row = %q, want the undetermined count", rows[0])
	}
	if strings.Contains(rows[1], "undetermined") {
		t.Errorf("row = %q, should omit undetermined when there are none", rows[1])
	}
}

func TestReachabilityBlockNamesUndeterminedOnlyWhenThereIsAny(t *testing.T) {
	_, notes := blockFor(engine.AnalyzerReachability{Analyzer: "govulncheck", Unreachable: 4})
	if len(notes) != 1 || !strings.Contains(notes[0], "ranked down in priority, not removed") {
		t.Fatalf("notes = %v", notes)
	}
	_, notes = blockFor(engine.AnalyzerReachability{Analyzer: "govulncheck", Unreachable: 4, Unknown: 3})
	if len(notes) != 2 || !strings.Contains(notes[1], "not analyzed") {
		t.Fatalf("notes = %v, want the undetermined caveat", notes)
	}
}

func TestReachabilityBlockNamesWhatOnlyOneAnalyzerFound(t *testing.T) {
	rows, _ := blockFor(engine.AnalyzerReachability{Analyzer: "govulncheck", Reachable: 2, Contributed: 1})
	if !strings.Contains(rows[0], "1 finding only it reported") {
		t.Errorf("row = %q", rows[0])
	}
}

func TestReachabilityBlockSilentWhenNothingRan(t *testing.T) {
	rows, notes := reachabilityBlock(Data{Run: engine.Result{}})
	if rows != nil || notes != nil {
		t.Errorf("rows=%v notes=%v, want nothing when no analyzer ran", rows, notes)
	}
}

func TestReachabilityNoteAccountsForABandThatMoved(t *testing.T) {
	// The counterpart of escalationNote: a high-severity finding sitting low is the one somebody
	// will ask about, so it says why.
	got := reachabilityNote(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
		RankedAs: sarif.SeverityMedium, AsOf: "2026-08-21",
	})
	for _, want := range []string{"↓", "ranked as medium", "never called", "govulncheck", "2026-08-21"} {
		if !strings.Contains(got, want) {
			t.Errorf("note %q missing %q", got, want)
		}
	}
}

func TestReachabilityNoteCarriesTheCallPath(t *testing.T) {
	got := reachabilityNote(&sarif.Reachability{
		State: sarif.ReachabilityReachable, Analyzer: "govulncheck", AsOf: "2026-08-21",
		Paths: []sarif.CallPath{
			{Frames: []sarif.CallFrame{{Function: "a"}, {Function: "b"}, {Function: "c"}}},
			{Frames: []sarif.CallFrame{{Function: "main"}, {Function: "ParseAcceptLanguage"}}},
		},
	})
	if !strings.Contains(got, "main → ParseAcceptLanguage") {
		t.Errorf("note %q does not carry the shortest call path", got)
	}
}

func TestReachabilityNoteSilentWhenNothingMoved(t *testing.T) {
	// Already at the lowest band: nothing moved, so there is nothing to account for.
	if got := reachabilityNote(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
	}); got != "" {
		t.Errorf("note = %q, want empty when the band did not move", got)
	}
	if got := reachabilityNote(&sarif.Reachability{State: sarif.ReachabilityUnknown}); got != "" {
		t.Errorf("undetermined note = %q, want empty", got)
	}
	if got := reachabilityNote(nil); got != "" {
		t.Errorf("nil note = %q", got)
	}
}

func TestReachabilityAttributionDegradesGracefully(t *testing.T) {
	// A verdict describes one revision of the code, so the date is the checkable part — but an
	// analyzer that reported none still gets named rather than going unattributed.
	dated := reachabilityNote(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
		RankedAs: sarif.SeverityLow, AsOf: "2026-08-21",
	})
	if !strings.HasSuffix(dated, "(govulncheck, 2026-08-21)") {
		t.Errorf("note = %q", dated)
	}
	undated := reachabilityNote(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck", RankedAs: sarif.SeverityLow,
	})
	if !strings.HasSuffix(undated, "(govulncheck)") {
		t.Errorf("note = %q", undated)
	}
	anonymous := reachabilityNote(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, RankedAs: sarif.SeverityLow,
	})
	if strings.Contains(anonymous, "(") {
		t.Errorf("note = %q, want no empty attribution", anonymous)
	}
}

func TestReachabilityNoteWithoutACallPath(t *testing.T) {
	// A reachable verdict whose analyzer reported no path still says it is reachable, which is
	// the part that changes what a reader does.
	got := reachabilityNote(&sarif.Reachability{State: sarif.ReachabilityReachable, Analyzer: "dep-scan"})
	if !strings.Contains(got, "reachable") || strings.Contains(got, ":") {
		t.Errorf("note = %q, want a bare reachable marker", got)
	}
}
