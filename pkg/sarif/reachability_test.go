package sarif

import "testing"

func TestDeescalateStopsAtLow(t *testing.T) {
	// One level down, and never to nothing. A call graph is evidence about how the code is called
	// today, not a proof the flaw cannot be triggered.
	for _, tc := range []struct{ from, want Severity }{
		{SeverityCritical, SeverityHigh},
		{SeverityHigh, SeverityMedium},
		{SeverityMedium, SeverityLow},
		{SeverityLow, SeverityLow},
		{"", ""},
	} {
		if got := tc.from.Deescalate(); got != tc.want {
			t.Errorf("%q.Deescalate() = %q, want %q", tc.from, got, tc.want)
		}
	}
}

func TestRankAtMovesNothing(t *testing.T) {
	// Reachable does not raise: severity already assumes the vulnerable code runs. Unreachable does
	// not lower: the call graph covers the builds analyzed, which are not yet every build a module
	// ships (https://github.com/draugr-dev/draugr/issues/2336).
	for _, tc := range []struct {
		name  string
		reach *Reachability
	}{
		{"no analysis", nil},
		{"reachable", &Reachability{State: ReachabilityReachable, Method: MethodCallGraph}},
		{"undetermined", &Reachability{State: ReachabilityUnknown, Method: MethodCallGraph}},
		{"unreachable by call graph", &Reachability{State: ReachabilityUnreachable, Method: MethodCallGraph}},
		{"unreachable by data flow", &Reachability{State: ReachabilityUnreachable, Method: MethodDataFlow}},
	} {
		if got := tc.reach.RankAt(SeverityHigh); got != SeverityHigh {
			t.Errorf("%s: RankAt(high) = %q, want high", tc.name, got)
		}
	}
}

func TestOnlyAStrongMethodProvesAbsence(t *testing.T) {
	// What separates them is what a *negative* is worth. A call graph that finds no path has
	// searched for one; a framework heuristic that finds no route has read a configuration file.
	// The report words the verdict by it, and lowering will rest on it once every build is analyzed.
	for method, want := range map[string]bool{
		MethodNotBuilt: false, MethodCallGraph: true, MethodDataFlow: true, MethodFrameworkHeuristic: false,
		MethodImportCheck: false, "": false, "whatever-ships-next": false,
	} {
		if got := ProvesAbsence(method); got != want {
			t.Errorf("ProvesAbsence(%q) = %v, want %v", method, got, want)
		}
	}
}

// A module the analyzed build does not compile moves nothing: the platforms analyzed may not be all
// that ship, so the finding is ranked, and judged, at the severity its scanner gave.
func TestNotBuiltMovesNothing(t *testing.T) {
	r := &Reachability{State: ReachabilityNotBuilt, Analyzer: "govulncheck", Method: MethodNotBuilt,
		Build: &AnalyzedBuild{Platforms: []string{"linux/amd64"}}}
	if got := r.RankAt(SeverityHigh); got != SeverityHigh {
		t.Errorf("RankAt(high) = %q, want high", got)
	}
	res := Result{Level: LevelError, Reachability: r}
	if got := res.RankedSeverity(); got != SeverityHigh {
		t.Errorf("ranked severity = %q, want the scanner's high", got)
	}
}

func TestEveryNamedMethodIsClassified(t *testing.T) {
	// A method constant added without a line in ProvesAbsence reads as unknown and silently stops
	// de-escalating, which looks like the analysis not running rather than like a missing case.
	strong := map[string]bool{
		MethodNotBuilt:           false,
		MethodCallGraph:          true,
		MethodDataFlow:           true,
		MethodFrameworkHeuristic: false,
		MethodImportCheck:        false,
	}
	for method, want := range strong {
		if got := ProvesAbsence(method); got != want {
			t.Errorf("ProvesAbsence(%q) = %v, want %v", method, got, want)
		}
	}
}

func TestReachabilityIsNotPartOfFingerprint(t *testing.T) {
	// A finding is the same finding whether or not analysis moved it. Folding this in would churn
	// every diff on the day a call is added or removed.
	base := Result{Tool: "trivy", RuleID: "CVE-2022-32149", Level: LevelError, Message: "m"}
	moved := base
	moved.Reachability = &Reachability{State: ReachabilityUnreachable, Analyzer: "govulncheck"}
	if base.Fingerprint() != moved.Fingerprint() {
		t.Error("reachability changed the fingerprint; diff would churn when a call is added")
	}
}

func TestReachabilitySurvivesSARIFRoundTrip(t *testing.T) {
	// A reachability verdict without its evidence is the claim readers are told to reject, and
	// the evidence is the part a consumer has no other way to get.
	in := Report{Tool: "draugr", Results: []Result{{
		Tool: "trivy", RuleID: "CVE-2022-32149", Level: LevelError, Message: "m",
		Package: &Package{Name: "golang.org/x/text"},
		Reachability: &Reachability{
			State: ReachabilityReachable, Analyzer: "govulncheck", Method: "call-graph",
			Symbols: []string{"golang.org/x/text/language.ParseAcceptLanguage"},
			Paths: []CallPath{{Frames: []CallFrame{
				{Function: "main", File: "main.go", Line: 11},
				{Function: "ParseAcceptLanguage", Module: "golang.org/x/text", File: "language/parse.go", Line: 775},
			}}},
		},
	}}}
	blob, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := FromSARIF(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Reachability == nil {
		t.Fatalf("reachability did not survive the file: %+v", out.Results)
	}
	got := out.Results[0].Reachability
	if got.State != ReachabilityReachable || got.Method != "call-graph" {
		t.Errorf("verdict = %+v", got)
	}
	if len(got.Paths) != 1 || len(got.Paths[0].Frames) != 2 {
		t.Fatalf("call path lost: %+v", got.Paths)
	}
	if got.Paths[0].Frames[0].Function != "main" {
		t.Errorf("path no longer reads caller first: %+v", got.Paths[0].Frames)
	}
}
