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

func TestParseLevelRejectsWhatItCannotRank(t *testing.T) {
	// An unknown level ranks 0 and every finding is at least 0, so an unvalidated typo turns a
	// gate into "fail on anything at all" — passing loudly while meaning something else entirely.
	for _, in := range []string{"error", "WARNING", " note "} {
		if _, err := ParseLevel(in); err != nil {
			t.Errorf("ParseLevel(%q): %v", in, err)
		}
	}
	for _, in := range []string{"banana", "", "P1", "err"} {
		if _, err := ParseLevel(in); err == nil {
			t.Errorf("ParseLevel(%q) was accepted", in)
		}
	}
}

func TestParseLevelExplainsTheSeverityMixUp(t *testing.T) {
	// The reports print critical/high/medium/low, so those are what someone reaches for. Listing
	// the three valid words without saying why theirs was not one of them leaves them guessing at
	// which of two ladders a flag is on.
	for _, in := range []string{"critical", "high", "medium", "low"} {
		_, err := ParseLevel(in)
		if err == nil {
			t.Fatalf("ParseLevel(%q) was accepted as a level", in)
		}
		if !strings.Contains(err.Error(), "severity band") {
			t.Errorf("ParseLevel(%q) = %v, want it to name the confusion", in, err)
		}
	}
}

func TestProvenanceRepository(t *testing.T) {
	p := Provenance{Tool: "trivy-fs", Fields: []Field{
		{Key: "repository", Value: "."},
		{Key: "revision", Value: "abc123def4567890"},
		{Key: "uncommitted", Value: "3"},
	}}
	got, ok := p.Repository()
	if !ok {
		t.Fatal("a repository entry was not recognised")
	}
	if got.URL != "." || got.Revision != "abc123def4567890" || got.Uncommitted != 3 {
		t.Errorf("Repository() = %+v", got)
	}
	if got.Short() != "abc123de" {
		t.Errorf("Short() = %q", got.Short())
	}

	// A scanner describing a benchmark rather than a checkout is not a repository, and treating
	// it as one would put a cluster scan under a heading about commits.
	other := Provenance{Tool: "kube-bench", Fields: []Field{{Key: "benchmark", Value: "cis-1.8"}}}
	if _, ok := other.Repository(); ok {
		t.Error("non-repository provenance was read as a repository")
	}

	// A revision short enough to be its own abbreviation, and a missing one.
	if s := (RepositoryRef{Revision: "abc"}).Short(); s != "abc" {
		t.Errorf("Short() = %q", s)
	}
	if s := (RepositoryRef{}).Short(); s != "" {
		t.Errorf("Short() = %q", s)
	}
	// An unparseable count is not worth failing over; it just means no count.
	bad := Provenance{Fields: []Field{{Key: "repository", Value: "."}, {Key: "uncommitted", Value: "many"}}}
	if r, _ := bad.Repository(); r.Uncommitted != 0 {
		t.Errorf("Uncommitted = %d", r.Uncommitted)
	}
}

func TestRepositoriesIn(t *testing.T) {
	entry := func(url, rev string) Report {
		return Report{Provenance: []Provenance{{Tool: "t", Fields: []Field{
			{Key: "repository", Value: url}, {Key: "revision", Value: rev},
		}}}}
	}
	// One checkout read by three controls is one fact.
	got := RepositoriesIn([]Report{entry(".", "aaa"), entry(".", "aaa"), entry(".", "aaa")})
	if len(got) != 1 {
		t.Errorf("expected one entry, got %+v", got)
	}
	// Two commits for one repository is a real event and stays visible.
	got = RepositoriesIn([]Report{entry(".", "aaa"), entry(".", "bbb")})
	if len(got) != 2 {
		t.Errorf("a mid-scan branch move was collapsed: %+v", got)
	}
	// Two repositories are two entries.
	got = RepositoriesIn([]Report{entry("a", "aaa"), entry("b", "aaa")})
	if len(got) != 2 {
		t.Errorf("expected both repositories, got %+v", got)
	}
	if RepositoriesIn(nil) != nil {
		t.Error("no reports should produce no repositories")
	}
}

// A finding's identity includes the repository it was found in.
//
// Paths are rewritten repository-relative so a finding can be anchored to a file, which means two
// repositories sharing a path share everything else. A component may hold several repositories,
// and a fragment may contribute one from another project — so the same secret in two of them is
// two leaked credentials, not one.
func TestFingerprintSeparatesRepositories(t *testing.T) {
	base := Result{Tool: "gitleaks", RuleID: "generic-api-key", Level: LevelError,
		Message: "secret", Location: Location{URI: "config.py", StartLine: 1}, Component: "platform"}
	alpha, beta := base, base
	alpha.Repository = "https://example.test/alpha"
	beta.Repository = "https://example.test/beta"

	if alpha.Fingerprint() == beta.Fingerprint() {
		t.Error("the same finding in two repositories is one finding; the second is discarded on merge")
	}
	// A descriptor with no multi-repository component is unaffected, so nothing changes for the
	// case almost every reader has: two separately-built identical findings still match.
	twin := Result{Tool: "gitleaks", RuleID: "generic-api-key", Level: LevelError,
		Message: "secret", Location: Location{URI: "config.py", StartLine: 1}, Component: "platform"}
	if base.Fingerprint() != twin.Fingerprint() {
		t.Error("identical findings with no repository should still match")
	}
}

// Component and repository have to survive being written and read back.
//
// Both are part of Fingerprint, and a report is written to a file and re-read by `draugr diff` on
// every pull request. An identity that only exists in memory is not one: the file said which
// component each finding belonged to, and the reader threw it away.
func TestSARIFRoundTripKeepsWhatIdentifiesAFinding(t *testing.T) {
	rep := Report{Tool: "Draugr", Results: []Result{
		{Tool: "gitleaks", RuleID: "generic-api-key", Level: LevelError, Message: "secret",
			Location:  Location{URI: "config.py", StartLine: 1},
			Component: "frontend", Repository: "https://example.test/alpha", Priority: "P1"},
		{Tool: "gitleaks", RuleID: "generic-api-key", Level: LevelError, Message: "secret",
			Location:  Location{URI: "config.py", StartLine: 1},
			Component: "backend", Repository: "https://example.test/alpha", Priority: "P4"},
	}}
	data, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	back, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != 2 {
		t.Fatalf("read back %d results, want 2", len(back.Results))
	}
	seen := map[string]bool{}
	for _, r := range back.Results {
		if r.Component == "" {
			t.Errorf("a finding came back with no component: %+v", r)
		}
		if r.Repository == "" {
			t.Errorf("a finding came back with no repository: %+v", r)
		}
		seen[r.Fingerprint()] = true
	}
	if len(seen) != 2 {
		t.Error("two findings came back sharing one identity; a diff would report only one of them")
	}
}

// Repository references are compared by what they name, not how they are spelled.
//
// A descriptor may say a clone URL, an ssh remote or a bare path; CI says "org/repo". Comparing
// them literally answers "different" for the same repository — and the caller of this drops
// findings on that answer, so a false negative loses a real finding.
func TestSameRepository(t *testing.T) {
	same := [][2]string{
		{"https://github.com/acme/web.git", "https://github.com/acme/web"},
		{"https://github.com/acme/web.git", "git@github.com:acme/web.git"},
		{"https://github.com/acme/web", "acme/web"},
		{"https://GITHUB.com/Acme/Web.git", "acme/web"},
		{"https://dev.azure.com/org/proj/_git/web", "proj/_git/web"},
		// A group's project, spelled every way a descriptor and a runner might.
		{"https://gitlab.com/acme/payments/api.git", "acme/payments/api"},
		{"https://gitlab.com/acme/payments/api", "git@gitlab.com:acme/payments/api.git"},
		{"https://gitlab.example.com:8443/acme/payments/api", "acme/payments/api"},
		{"https://oauth2:token@gitlab.com/acme/payments/api", "acme/payments/api"},
	}
	for _, p := range same {
		if !SameRepository(p[0], p[1]) {
			t.Errorf("SameRepository(%q, %q) = false, want true", p[0], p[1])
		}
	}
	differ := [][2]string{
		{"https://github.com/acme/web", "https://github.com/acme/api"},
		{"https://github.com/acme/web", "https://github.com/other/web"},
		{"", "acme/web"}, // nothing to compare is not a match
		{"acme/web", ""}, // and neither is the other way round
		// Sibling groups. Keeping only the last two segments made these one repository, and the
		// findings of both were reported under whichever was seen last.
		{"https://gitlab.com/payments/backend/api", "https://gitlab.com/platform/backend/api"},
		{"git@gitlab.com:payments/backend/api.git", "git@gitlab.com:platform/backend/api.git"},
		// A bare name says which repository only if there is exactly one of them, which is not
		// something this can know.
		{"https://gitlab.com/payments/backend/api", "api"},
		// A group may legally carry a dot. Treating the first segment as a hostname because it
		// looks like one would strip it, and collapse these two.
		{"acme.corp/api", "other.corp/api"},
	}
	for _, p := range differ {
		if SameRepository(p[0], p[1]) {
			t.Errorf("SameRepository(%q, %q) = true, want false", p[0], p[1])
		}
	}
}
