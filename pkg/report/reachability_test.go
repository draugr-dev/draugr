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
	// "unknown" is what the descriptor, the schema and report.json call it, so it is what the
	// terminal calls it too.
	if !strings.Contains(rows[0], "3 unknown") {
		t.Errorf("row = %q, want the unknown count", rows[0])
	}
	if strings.Contains(rows[1], "unknown") {
		t.Errorf("row = %q, should omit the count when there are none", rows[1])
	}
}

func TestReachabilityBlockNamesTheUnknownOnlyWhenThereIsAny(t *testing.T) {
	_, notes := blockFor(engine.AnalyzerReachability{Analyzer: "govulncheck", Unreachable: 4})
	if len(notes) != 1 || !strings.Contains(notes[0], "ranked down in priority, not removed") {
		t.Fatalf("notes = %v", notes)
	}
	_, notes = blockFor(engine.AnalyzerReachability{Analyzer: "govulncheck", Unreachable: 4, Unknown: 3})
	if len(notes) != 2 || !strings.Contains(notes[1], "did not cover it") {
		t.Fatalf("notes = %v, want the caveat about what was not analyzed", notes)
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

func TestUnreachableCreditNamesWhoLoweredIt(t *testing.T) {
	// The row is marked, so the line under it carries what the mark cannot: which analyzer decided
	// nothing calls this, and the day it decided.
	got := unreachableCredit(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
		RankedAs: sarif.SeverityMedium, AsOf: "2026-08-21",
	})
	if got != "govulncheck, 2026-08-21" {
		t.Errorf("credit = %q", got)
	}
	// An analyzer that reported no date still gets named rather than going unattributed.
	got = unreachableCredit(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck", RankedAs: sarif.SeverityLow,
	})
	if got != "govulncheck" {
		t.Errorf("credit = %q", got)
	}
	// Nothing to credit, rather than an empty pair of brackets.
	if got := unreachableCredit(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, RankedAs: sarif.SeverityLow,
	}); got != "" {
		t.Errorf("credit = %q, want nothing where no analyzer is named", got)
	}
	// Already at the lowest band: nothing moved, so there is nothing to account for.
	if got := unreachableCredit(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
	}); got != "" {
		t.Errorf("credit = %q, want empty when the band did not move", got)
	}
	if got := unreachableCredit(nil); got != "" {
		t.Errorf("nil credit = %q", got)
	}
}

func TestReachabilityPathCarriesTheShortestRoute(t *testing.T) {
	got := reachabilityPath(&sarif.Reachability{
		State: sarif.ReachabilityReachable, Analyzer: "govulncheck", AsOf: "2026-08-21",
		Paths: []sarif.CallPath{
			{Frames: []sarif.CallFrame{{Function: "a"}, {Function: "b"}, {Function: "c"}}},
			{Frames: []sarif.CallFrame{{Function: "main"}, {Function: "ParseAcceptLanguage"}}},
		},
	})
	if !strings.Contains(got, "main → ParseAcceptLanguage") {
		t.Errorf("note %q does not carry the shortest call path", got)
	}
	// A reachable verdict whose analyzer reported no path still says it is reachable, which is
	// the part that changes what a reader does.
	got = reachabilityPath(&sarif.Reachability{State: sarif.ReachabilityReachable, Analyzer: "dep-scan"})
	if !strings.Contains(got, "reachable") || strings.Contains(got, ":") {
		t.Errorf("note = %q, want a bare reachable marker", got)
	}
	// Nothing to say about the other two verdicts: one is marked on the row, the other is silence.
	if got := reachabilityPath(&sarif.Reachability{
		State: sarif.ReachabilityUnreachable, RankedAs: sarif.SeverityLow,
	}); got != "" {
		t.Errorf("unreachable path = %q", got)
	}
	if got := reachabilityPath(&sarif.Reachability{State: sarif.ReachabilityUnknown}); got != "" {
		t.Errorf("unknown path = %q", got)
	}
	if got := reachabilityPath(nil); got != "" {
		t.Errorf("nil path = %q", got)
	}
}

func TestAgreementNoteShowsARatingOnlyWhenItDiffers(t *testing.T) {
	// Where the scanners agree, repeating the same numbers on every row is noise. Where they
	// disagree, it is the one thing this line carries that a reader cannot get anywhere else.
	agree := agreementNote([]sarif.Observation{
		{Tool: "grype", Severity: sarif.SeverityHigh, Score: 8.7},
	}, sarif.SeverityHigh)
	if agree != "also found by grype" {
		t.Errorf("note = %q, want no rating when they agree", agree)
	}

	differ := agreementNote([]sarif.Observation{
		{Tool: "grype", Severity: sarif.SeverityLow, Score: 2.3},
	}, sarif.SeverityMedium)
	if differ != "also found by grype (low 2.3)" {
		t.Errorf("note = %q, want the other scanner's own reading", differ)
	}
}

func TestAgreementNoteHandlesSeveralScanners(t *testing.T) {
	got := agreementNote([]sarif.Observation{
		{Tool: "grype", Severity: sarif.SeverityLow, Score: 2.3},
		{Tool: "osv", Severity: sarif.SeverityMedium},
	}, sarif.SeverityMedium)
	if got != "also found by grype (low 2.3), osv" {
		t.Errorf("note = %q", got)
	}
}

func TestAgreementNoteSilentWhenOnlyOneScannerFoundIt(t *testing.T) {
	if got := agreementNote(nil, sarif.SeverityHigh); got != "" {
		t.Errorf("note = %q, want nothing", got)
	}
}
