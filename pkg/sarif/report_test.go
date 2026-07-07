package sarif

import "testing"

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
	if base.Fingerprint() != base.Fingerprint() {
		t.Fatal("fingerprint must be stable")
	}
	other := base
	other.Location.StartLine = 2
	if base.Fingerprint() == other.Fingerprint() {
		t.Error("different location should change fingerprint")
	}
}
