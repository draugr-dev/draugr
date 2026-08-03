package sarif

import (
	"encoding/json"
	"strings"
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

// Two scanners serving one control each have their own account, and both belong in the evidence.
// Flattening them would keep whichever was written last — the failure this type exists to stop.
func TestMergeKeepsEveryScannersProvenance(t *testing.T) {
	t.Parallel()

	a := Report{Tool: "kube-bench-job", Provenance: []Provenance{{
		Tool: "kube-bench-job", Version: "0.15.6",
		Fields: []Field{{Key: "benchmark", Value: "gke-1.9.0"}},
	}}}
	b := Report{Tool: "draugr-k8s-policies", Provenance: []Provenance{{
		Tool:   "draugr-k8s-policies",
		Fields: []Field{{Key: "benchmark", Value: "cis-1.12"}, {Key: "coverage", Value: "20 of 34 decided"}},
	}}}

	got := Merge(a, b)
	if len(got.Provenance) != 2 {
		t.Fatalf("want both accounts, got %d: %+v", len(got.Provenance), got.Provenance)
	}

	// Merging is not idempotent by accident: aggregation merges repeatedly, and a report merged
	// with itself must not double its own history.
	twice := Merge(got, got)
	if len(twice.Provenance) != 2 {
		t.Errorf("re-merging duplicated provenance: %+v", twice.Provenance)
	}
}

// An entry saying nothing is noise in every report that renders it.
func TestMergeDropsEmptyProvenance(t *testing.T) {
	t.Parallel()
	got := Merge(Report{Tool: "x", Provenance: []Provenance{{Tool: "x"}}})
	if len(got.Provenance) != 0 {
		t.Errorf("an entry with no version and no fields says nothing: %+v", got.Provenance)
	}
}

// Describe is what a reporter with one line to spend renders.
func TestProvenanceDescribe(t *testing.T) {
	t.Parallel()
	p := Provenance{Fields: []Field{{Key: "benchmark", Value: "cis-1.12"}, {Key: "coverage", Value: "20 of 34"}}}
	if got, want := p.Describe(), "benchmark cis-1.12 · coverage 20 of 34"; got != want {
		t.Errorf("Describe() = %q, want %q", got, want)
	}
	// Order is the scanner's choice, not alphabetical — "coverage" must not sort ahead of
	// "benchmark".
	if strings.Index(p.Describe(), "benchmark") > strings.Index(p.Describe(), "coverage") {
		t.Error("fields should render in the order the scanner gave them")
	}
}

// Two components sharing a repository hit the same flaw at the same line, and it is not the same
// finding: each carries its own component's exposure and criticality, so one can be P1 and the
// other P4. Collapsing them kept whichever merged first and discarded the other — which could be
// the urgent one, and contradicts the claim that context decides priority.
func TestFingerprintSeparatesComponents(t *testing.T) {
	t.Parallel()

	base := Result{Tool: "gitleaks", RuleID: "github-pat", Level: LevelError,
		Message: "token", Location: Location{URI: "config.txt", StartLine: 1}}
	payments := base
	payments.Component = "payments"
	internal := base
	internal.Component = "internal-tool"

	if payments.Fingerprint() == internal.Fingerprint() {
		t.Fatal("the same flaw in two components is two findings, not one")
	}

	merged := Merge(Report{Tool: "gitleaks", Results: []Result{payments, internal}})
	if len(merged.Results) != 2 {
		t.Errorf("merge kept %d of 2 findings", len(merged.Results))
	}

	// Within one component it is still one finding — this must not become a way to duplicate.
	twice := Merge(Report{Tool: "gitleaks", Results: []Result{payments, payments}})
	if len(twice.Results) != 1 {
		t.Errorf("the same finding in the same component is one, got %d", len(twice.Results))
	}
}
