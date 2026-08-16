package sarif

import (
	"strings"
	"testing"
)

func TestLevelRankOrdering(t *testing.T) {
	if LevelError.Rank() <= LevelWarning.Rank() {
		t.Error("error should outrank warning")
	}
	if LevelWarning.Rank() <= LevelNote.Rank() {
		t.Error("warning should outrank note")
	}
	if LevelNote.Rank() <= LevelNone.Rank() {
		t.Error("note should outrank none")
	}
	if Level("bogus").Rank() != 0 {
		t.Error("unknown level should have rank 0")
	}
}

func TestAtLeast(t *testing.T) {
	if !LevelError.AtLeast(LevelWarning) {
		t.Error("error should be at least warning")
	}
	if LevelNote.AtLeast(LevelError) {
		t.Error("note should not be at least error")
	}
	if !LevelWarning.AtLeast(LevelWarning) {
		t.Error("warning should be at least warning (equal)")
	}
}

func TestSeverityFromScoreBands(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{9.8, SeverityCritical}, {9.0, SeverityCritical},
		{8.9, SeverityHigh}, {7.0, SeverityHigh},
		{6.9, SeverityMedium}, {4.0, SeverityMedium},
		{3.9, SeverityLow}, {0.0, SeverityLow},
	}
	for _, tc := range cases {
		if got := severityFromScore(tc.score); got != tc.want {
			t.Errorf("severityFromScore(%.1f) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestResultSeverityResolution(t *testing.T) {
	// 1. Numeric score wins when present.
	scored := Result{Level: LevelWarning, Score: 9.1, HasScore: true}
	if got := scored.Severity(""); got != SeverityCritical {
		t.Errorf("scored severity = %q, want critical (score beats level)", got)
	}
	// 2. Falls back to the SARIF level when there's no score.
	unscored := Result{Level: LevelError}
	if got := unscored.Severity(""); got != SeverityHigh {
		t.Errorf("unscored severity = %q, want high (error→high)", got)
	}
	// 3. Floor raises a low finding but never lowers a higher one.
	lowSecret := Result{Level: LevelNote} // → low
	if got := lowSecret.Severity(SeverityHigh); got != SeverityHigh {
		t.Errorf("floored severity = %q, want high (floor raises)", got)
	}
	if got := scored.Severity(SeverityMedium); got != SeverityCritical {
		t.Errorf("floor should not lower a critical, got %q", got)
	}
}

func TestSeverityRankAndAtLeast(t *testing.T) {
	ranks := []int{SeverityCritical.Rank(), SeverityHigh.Rank(), SeverityMedium.Rank(), SeverityLow.Rank()}
	for i := 1; i < len(ranks); i++ {
		if ranks[i] >= ranks[i-1] {
			t.Errorf("severity ranks should be strictly descending: %v", ranks)
		}
	}
	if Severity("").Rank() != 0 {
		t.Error("empty severity should rank 0")
	}
	if !SeverityCritical.AtLeast(SeverityLow) || SeverityLow.AtLeast(SeverityHigh) {
		t.Error("AtLeast comparison wrong")
	}
}

// TestParseSeverityTakesTheWordsTheReportPrints, which is the point of the change: a threshold is
// written in the same vocabulary as the counts beside it.
func TestParseSeverityTakesTheWordsTheReportPrints(t *testing.T) {
	for in, want := range map[string]Severity{
		"critical": SeverityCritical,
		"high":     SeverityHigh,
		"medium":   SeverityMedium,
		"low":      SeverityLow,
		"  HIGH ":  SeverityHigh,
	} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestParseSeverityStillTakesTheLevelsAGateUsedTo: a descriptor or pipeline written against the
// older vocabulary keeps working, rather than failing at the point it is least convenient.
func TestParseSeverityStillTakesTheLevelsAGateUsedTo(t *testing.T) {
	for in, want := range map[string]Severity{
		"error":   SeverityHigh,
		"warning": SeverityMedium,
		"note":    SeverityLow,
	} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestParseSeverityRefusesAWordItDoesNotKnow. A threshold nobody can parse quietly becoming the
// default is a gate that passes for a reason its author never chose.
func TestParseSeverityRefusesAWordItDoesNotKnow(t *testing.T) {
	for _, in := range []string{"", "urgent", "P1", "sev1"} {
		if _, err := ParseSeverity(in); err == nil {
			t.Errorf("ParseSeverity(%q) should have failed", in)
		}
	}
	err := func() error { _, e := ParseSeverity("urgent"); return e }()
	for _, want := range []string{"critical", "high", "medium", "low"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %q: %v", want, err)
		}
	}
}

// TestHighestSeverityPrefersTheScoreOverTheLevel is the mismatch the gate used to miss.
func TestHighestSeverityPrefersTheScoreOverTheLevel(t *testing.T) {
	r := Report{Results: []Result{
		{RuleID: "a", Level: LevelNote},
		{RuleID: "b", Level: LevelWarning, HasScore: true, Score: 7.8},
	}}
	if got := r.HighestSeverity(); got != SeverityHigh {
		t.Errorf("HighestSeverity = %q, want high", got)
	}
}

// TestHighestSeverityIgnoresSuppressed: an exclusion that stops a finding counting has to stop it
// gating too, or the count drops to zero while the build still fails on it.
func TestHighestSeverityIgnoresSuppressed(t *testing.T) {
	r := Report{Results: []Result{{
		RuleID: "a", Level: LevelError, HasScore: true, Score: 9.8,
		Suppression: &Suppression{Justification: "accepted", Kind: "external"},
	}}}
	if got := r.HighestSeverity(); got != "" {
		t.Errorf("a suppressed finding was judged: %q", got)
	}
}

// TestHighestSeverityOfNothing is the empty report, which must not read as a band.
func TestHighestSeverityOfNothing(t *testing.T) {
	if got := (Report{}).HighestSeverity(); got != "" {
		t.Errorf("an empty report has no band, got %q", got)
	}
}
