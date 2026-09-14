package sarif

import "testing"

func TestDeescalateStopsAtLow(t *testing.T) {
	// One band down, and never to nothing. A call graph is evidence about how the code is called
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

func TestRankAtOnlyMovesUnreachable(t *testing.T) {
	// Reachable does not raise: severity already assumes the vulnerable code runs, so treating a
	// confirmed call as an escalation would count the same assumption twice.
	for _, tc := range []struct {
		name  string
		reach *Reachability
		want  Severity
	}{
		{"no analysis", nil, SeverityHigh},
		{"reachable", &Reachability{State: ReachabilityReachable, Method: MethodCallGraph}, SeverityHigh},
		{"undetermined", &Reachability{State: ReachabilityUnknown, Method: MethodCallGraph}, SeverityHigh},
		{"unreachable", &Reachability{State: ReachabilityUnreachable, Method: MethodCallGraph}, SeverityMedium},
	} {
		if got := tc.reach.RankAt(SeverityHigh); got != tc.want {
			t.Errorf("%s: RankAt(high) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestOnlyAStrongMethodLowersABand(t *testing.T) {
	// What separates the four is what a *negative* is worth. A call graph that finds no path has
	// searched for one; a framework heuristic that finds no route has read a configuration file,
	// and a band lowered on that is a finding somebody stops looking at on the strength of a guess.
	for _, tc := range []struct {
		method string
		want   Severity
	}{
		{MethodCallGraph, SeverityMedium},
		{MethodDataFlow, SeverityMedium},
		{MethodFrameworkHeuristic, SeverityHigh},
		{MethodImportCheck, SeverityHigh},
		{"", SeverityHigh},
		{"whatever-ships-next", SeverityHigh},
	} {
		reach := &Reachability{State: ReachabilityUnreachable, Method: tc.method}
		if got := reach.RankAt(SeverityHigh); got != tc.want {
			t.Errorf("method %q: RankAt(high) = %q, want %q", tc.method, got, tc.want)
		}
	}
}

func TestEveryNamedMethodIsClassified(t *testing.T) {
	// A method constant added without a line in ProvesAbsence reads as unknown and silently stops
	// de-escalating, which looks like the analysis not running rather than like a missing case.
	strong := map[string]bool{
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
