package sarif

import "testing"

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
