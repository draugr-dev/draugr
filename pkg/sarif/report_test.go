package sarif

import (
	"encoding/json"
	"testing"
)

func TestMergeDeduplicates(t *testing.T) {
	a := Report{Tool: "trivy", Results: []Result{
		{RuleID: "CVE-1", Level: LevelError, Message: "boom", Location: Location{URI: "img"}},
		{RuleID: "CVE-2", Level: LevelWarning, Message: "meh"},
	}}
	b := Report{Tool: "trivy", Results: []Result{
		{RuleID: "CVE-1", Level: LevelError, Message: "boom", Location: Location{URI: "img"}}, // dup of a[0]
		{RuleID: "CVE-3", Level: LevelNote, Message: "fyi"},
	}}

	m := Merge(a, b)
	if len(m.Results) != 3 {
		t.Fatalf("merged results = %d, want 3 (one dup removed)", len(m.Results))
	}
	if m.Results[0].RuleID != "CVE-1" || m.Results[2].RuleID != "CVE-3" {
		t.Errorf("order not preserved: %+v", m.Results)
	}
}

func TestMergeBackfillsTool(t *testing.T) {
	r := Report{Tool: "grype", Results: []Result{{RuleID: "X", Level: LevelNote}}}
	m := Merge(r)
	if m.Results[0].Tool != "grype" {
		t.Errorf("tool not backfilled: %q", m.Results[0].Tool)
	}
}

func TestDedupWithinReport(t *testing.T) {
	r := Report{Tool: "t", Results: []Result{
		{RuleID: "A", Level: LevelNote},
		{RuleID: "A", Level: LevelNote},
	}}
	if got := len(r.Dedup().Results); got != 1 {
		t.Fatalf("dedup = %d results, want 1", got)
	}
}

func TestCountsAndHighest(t *testing.T) {
	r := Report{Results: []Result{
		{Level: LevelError}, {Level: LevelWarning}, {Level: LevelWarning}, {Level: LevelNote}, {Level: LevelNone},
	}}
	c := r.Counts()
	if c.Error != 1 || c.Warning != 2 || c.Note != 1 || c.None != 1 {
		t.Fatalf("counts = %+v", c)
	}
	if c.Total() != 5 {
		t.Errorf("total = %d, want 5", c.Total())
	}
	if r.Highest() != LevelError {
		t.Errorf("highest = %q, want error", r.Highest())
	}
}

func TestHighestEmpty(t *testing.T) {
	if (Report{}).Highest() != LevelNone {
		t.Error("empty report highest should be none")
	}
}

func TestFingerprintDistinguishes(t *testing.T) {
	base := Result{Tool: "t", RuleID: "R", Level: LevelError, Message: "m", Location: Location{URI: "u", StartLine: 1}}
	sameContent := Result{Tool: "t", RuleID: "R", Level: LevelError, Message: "m", Location: Location{URI: "u", StartLine: 1}}
	if base.Fingerprint() != sameContent.Fingerprint() {
		t.Fatal("fingerprint must be stable for identical content")
	}
	other := base
	other.Location.StartLine = 2
	if base.Fingerprint() == other.Fingerprint() {
		t.Error("different location should change fingerprint")
	}
}

func TestHighestIgnoresSuppressedFindings(t *testing.T) {
	// Highest drives the gate. If it counted a suppressed finding, an exclusion would look like
	// it worked — the counts drop to zero — while the build still failed on the very finding
	// the Saga set aside. That is worse than not having exclusions at all.
	r := Report{Results: []Result{
		{RuleID: "a", Level: LevelError, Suppression: &Suppression{Kind: "external", Justification: "fixture"}},
		{RuleID: "b", Level: LevelNote},
	}}
	if got := r.Highest(); got != LevelNote {
		t.Errorf("Highest() = %q, want %q — the error is suppressed", got, LevelNote)
	}
	if c := r.Counts(); c.Error != 0 || c.Note != 1 {
		t.Errorf("Counts() = %+v, want only the unsuppressed note", c)
	}
}

func TestSuppressionSurvivesAMarshalRoundTrip(t *testing.T) {
	// The evidence has to reach the file. A suppressed finding that silently vanished on write
	// would be a deletion wearing a different name.
	r := Report{Tool: "t", Results: []Result{{
		RuleID: "private-key", Level: LevelError,
		Location:    Location{URI: "test/fixture.go", StartLine: 1},
		Suppression: &Suppression{Kind: "external", Justification: "deliberate test fixture"},
	}}}
	b, err := r.MarshalSARIF()
	if err != nil {
		t.Fatalf("MarshalSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Suppressions []struct{ Kind, Justification string } `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("want the suppressed result still emitted, got %s", b)
	}
	sup := doc.Runs[0].Results[0].Suppressions
	if len(sup) != 1 || sup[0].Kind != "external" || sup[0].Justification != "deliberate test fixture" {
		t.Errorf("suppressions = %+v, want the kind and justification", sup)
	}
}
