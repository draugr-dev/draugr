package vex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimal = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://acme.example/vex/api-1",
  "author": "Acme Ltd <security@acme.example>",
  "timestamp": "2026-08-01T09:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2024-1111"},
      "products": [
        {
          "@id": "pkg:oci/acme/api@sha256:abc",
          "subcomponents": [{"@id": "pkg:deb/debian/openssl@3.0.11"}]
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}`

func TestReadParsesADocument(t *testing.T) {
	doc, err := Read(strings.NewReader(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Author != "Acme Ltd <security@acme.example>" {
		t.Errorf("author = %q", doc.Author)
	}
	if doc.ID == "" || doc.Timestamp == "" {
		t.Error("id and timestamp are what let a reader tell one revision from another")
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(doc.Statements))
	}
}

// OpenVEX 0.1.0 wrote the vulnerability as a bare string. A supplier who has not revised their
// tooling is exactly the supplier whose claims are hardest to obtain, so refusing the older shape
// would drop the documents this feature exists to read.
func TestTheOlderStringVulnerabilityIsStillRead(t *testing.T) {
	old := strings.Replace(minimal,
		`"vulnerability": {"name": "CVE-2024-1111"}`,
		`"vulnerability": "CVE-2024-1111"`, 1)
	doc, err := Read(strings.NewReader(old))
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Statements[0].Vulnerability.Name; got != "CVE-2024-1111" {
		t.Errorf("vulnerability = %q, want CVE-2024-1111", got)
	}
}

// A document that cannot be acted on is refused, and says why. Accepting one silently would let a
// typo in a supplier's status read as "no claims apply", which is indistinguishable from a
// document that legitimately excused nothing.
func TestADocumentThatCannotBeActedOnIsRefused(t *testing.T) {
	cases := []struct {
		name, doc, want string
	}{
		{"not json", `{`, "not a readable OpenVEX document"},
		{"no statements", `{"@context":"x","statements":[]}`, "no statements"},
		{"statement with no status",
			`{"statements":[{"vulnerability":{"name":"CVE-1"}}]}`, "no status"},
		{"status outside the vocabulary",
			`{"statements":[{"vulnerability":{"name":"CVE-1"},"status":"probably_fine"}]}`,
			"which is not one of"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(c.doc))
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestLoadNamesTheFileItCouldNotRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "bad.json") {
		t.Errorf("error = %v, want it to name the file", err)
	}
	if _, err := Load(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("a missing document should be an error, not an empty one")
	}
	doc, err := Load(writeDoc(t, dir, "good.json", minimal))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 1 {
		t.Errorf("statements = %d, want 1", len(doc.Statements))
	}
}

func writeDoc(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A supplier says "our product is not affected by CVE-X, which is in libfoo". libfoo is what the
// scan found, so the subcomponent is the identifier that has to match — matching only the product
// would miss the shape most real documents take.
func TestASubcomponentIsWhatAFindingMatches(t *testing.T) {
	doc, err := Read(strings.NewReader(minimal))
	if err != nil {
		t.Fatal(err)
	}
	claims := doc.Claims("vendor/acme.json")
	if len(claims) != 1 {
		t.Fatalf("claims = %d, want 1", len(claims))
	}
	c := claims[0]
	if c.PURL != "pkg:deb/debian/openssl@3.0.11" {
		t.Errorf("purl = %q, want the subcomponent rather than the product", c.PURL)
	}
	if c.Author == "" || c.Source != "vendor/acme.json" || c.Timestamp == "" {
		t.Errorf("a claim must carry who said it, where from and when: %+v", c)
	}
}

// Two identifiers for the same package have to meet. A qualifier the scanner emits and the
// supplier does not is the most common way a correct statement matches nothing at all.
func TestPackageIdentifiersMeetDespiteQualifiers(t *testing.T) {
	cases := []struct{ a, b string }{
		{"pkg:deb/debian/openssl@3.0.11?arch=amd64", "pkg:deb/debian/openssl@3.0.11"},
		{"pkg:golang/github.com/foo/bar@v1.2.3#subdir", "pkg:golang/github.com/foo/bar@v1.2.3"},
		{"PKG:DEB/debian/openssl@3.0.11", "pkg:deb/debian/openssl@3.0.11"},
	}
	for _, c := range cases {
		if got, want := normalizePURL(c.a), normalizePURL(c.b); got != want {
			t.Errorf("normalize(%q) = %q, want it to equal normalize(%q) = %q", c.a, got, c.b, want)
		}
	}
	// The name and version are case-sensitive, and flattening them would merge packages that are
	// genuinely different.
	if normalizePURL("pkg:golang/github.com/Masterminds/semver") ==
		normalizePURL("pkg:golang/github.com/masterminds/semver") {
		t.Error("package names are case-sensitive and must not be folded together")
	}
	// A non-purl identifier is left exactly as written.
	if got := normalizePURL("https://acme.example/products/api"); got != "https://acme.example/products/api" {
		t.Errorf("non-purl identifier = %q, want it untouched", got)
	}
}

// The safety direction of the whole format. Believing the safer of two contradictory supplier
// claims is how a tool talks somebody into shipping something.
func TestTheClaimConcedingMoreExposureWins(t *testing.T) {
	ix := NewIndex([]Claim{
		{Vulnerability: "CVE-1", PURL: "pkg:deb/x@1", Status: "not_affected"},
		{Vulnerability: "CVE-1", PURL: "pkg:deb/x@1", Status: "affected"},
	})
	c, _, ok := ix.Lookup("CVE-1", "pkg:deb/x@1")
	if !ok {
		t.Fatal("expected a claim")
	}
	if c.Status != "affected" {
		t.Errorf("status = %q, want affected — the stronger claim of exposure", c.Status)
	}

	// And the same in the other order, so the result does not depend on document order.
	ix = NewIndex([]Claim{
		{Vulnerability: "CVE-1", PURL: "pkg:deb/x@1", Status: "affected"},
		{Vulnerability: "CVE-1", PURL: "pkg:deb/x@1", Status: "not_affected"},
	})
	c, _, _ = ix.Lookup("CVE-1", "pkg:deb/x@1")
	if c.Status != "affected" {
		t.Errorf("status = %q, want affected regardless of the order read", c.Status)
	}
}

// A statement naming the package is the one the supplier thought about, so it beats a blanket one.
func TestTheSpecificClaimBeatsTheBlanketOne(t *testing.T) {
	ix := NewIndex([]Claim{
		{Vulnerability: "CVE-1", Status: "not_affected", Statement: "blanket"},
		{Vulnerability: "CVE-1", PURL: "pkg:deb/x@1", Status: "affected", Statement: "specific"},
	})
	c, _, ok := ix.Lookup("CVE-1", "pkg:deb/x@1")
	if !ok || c.Statement != "specific" {
		t.Errorf("claim = %+v, want the one naming the package", c)
	}
	// A finding for another package still gets the blanket claim.
	c, _, ok = ix.Lookup("CVE-1", "pkg:deb/other@2")
	if !ok || c.Statement != "blanket" {
		t.Errorf("claim = %+v, want the blanket one", c)
	}
}

// Only a claim that excuses exposure may suppress. A supplier telling you that you *are* affected
// must never be the reason a finding stops being counted.
func TestOnlyAnExcusingStatusSuppresses(t *testing.T) {
	for status, want := range map[string]bool{
		"not_affected":        true,
		"fixed":               true,
		"affected":            false,
		"under_investigation": false,
	} {
		if got := Suppresses(status); got != want {
			t.Errorf("Suppresses(%q) = %v, want %v", status, got, want)
		}
	}
}

// The key a lookup used comes back with it, because the two maps are keyed differently — and a
// caller recording the wrong key would tell a supplier their applied statement was ignored.
func TestUnmatchedReportsOnlyWhatWasNeverUsed(t *testing.T) {
	ix := NewIndex([]Claim{
		{Vulnerability: "CVE-1", PURL: "pkg:deb/x@1", Status: "not_affected"},
		{Vulnerability: "CVE-2", Status: "not_affected"},
		{Vulnerability: "CVE-3", PURL: "pkg:deb/z@9", Status: "not_affected"},
	})
	used := map[string]bool{}

	// A finding for a package with no specific claim falls through to the blanket CVE-2 claim.
	_, key, ok := ix.Lookup("CVE-2", "pkg:deb/anything@1")
	if !ok {
		t.Fatal("expected the blanket claim to apply")
	}
	used[key] = true

	_, key, _ = ix.Lookup("CVE-1", "pkg:deb/x@1")
	used[key] = true

	un := ix.Unmatched(used)
	if len(un) != 1 {
		t.Fatalf("unmatched = %d (%+v), want only CVE-3", len(un), un)
	}
	if un[0].Vulnerability != "CVE-3" {
		t.Errorf("unmatched = %q, want CVE-3", un[0].Vulnerability)
	}
}

func TestAgeReportsTheClaimsOwnDate(t *testing.T) {
	doc, err := Read(strings.NewReader(minimal))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC)
	age, ok := doc.Age(now)
	if !ok {
		t.Fatal("a document with a timestamp should report its age")
	}
	if want := 17 * 24 * time.Hour; age != want {
		t.Errorf("age = %v, want %v", age, want)
	}
	// A document with no timestamp says so rather than claiming to be new.
	if _, ok := (Document{}).Age(now); ok {
		t.Error("an absent timestamp must not read as an age of zero")
	}
	if _, ok := (Document{Timestamp: "last tuesday"}).Age(now); ok {
		t.Error("an unparseable timestamp must not read as an age of zero")
	}
}

// A statement with no products still says something, and is kept — narrowed by the component that
// declared the source rather than dropped.
func TestAStatementWithNoProductsStillCounts(t *testing.T) {
	doc, err := Read(strings.NewReader(
		`{"author":"A","timestamp":"2026-08-01T09:00:00Z","statements":[
		   {"vulnerability":{"name":"CVE-9"},"status":"not_affected"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	claims := doc.Claims("s.json")
	if len(claims) != 1 || claims[0].PURL != "" {
		t.Fatalf("claims = %+v, want one claim applying to any package", claims)
	}
	// And a statement naming no vulnerability is dropped, because nothing could match it.
	doc.Statements = append(doc.Statements, Statement{Status: "not_affected"})
	if got := len(doc.Claims("s.json")); got != 1 {
		t.Errorf("claims = %d, want the unidentifiable statement dropped", got)
	}
}

// prose picks the human half of a statement, preferring what the supplier actually wrote. A
// vocabulary term is machine-readable and says nothing to somebody reading the report.
func TestProsePrefersWhatTheSupplierWrote(t *testing.T) {
	cases := []struct {
		st   Statement
		want string
	}{
		{Statement{ImpactStatement: "impact", ActionStatement: "action", StatusNotes: "notes"}, "impact"},
		{Statement{ActionStatement: "action", StatusNotes: "notes"}, "action"},
		{Statement{StatusNotes: "notes"}, "notes"},
		{Statement{}, ""},
	}
	for _, c := range cases {
		if got := prose(c.st); got != c.want {
			t.Errorf("prose(%+v) = %q, want %q", c.st, got, c.want)
		}
	}
}

func TestAProductWithoutSubcomponentsMatchesOnTheProduct(t *testing.T) {
	d := Document{Author: "A", Statements: []Statement{{
		Vulnerability: Vulnerability{Name: "CVE-1"},
		Products:      []Product{{ID: "pkg:oci/acme/api@sha256:abc"}},
		Status:        "not_affected",
	}}}
	claims := d.Claims("s.json")
	if len(claims) != 1 || claims[0].PURL != "pkg:oci/acme/api@sha256:abc" {
		t.Fatalf("claims = %+v, want the product used when no subcomponent was named", claims)
	}
}

func TestSetHelpers(t *testing.T) {
	if !(Set{}).Empty() {
		t.Error("a set with nothing in it is empty")
	}
	s := Set{
		Project:     []Resolved{{Provenance: Provenance{Location: "p.json"}}},
		ByComponent: map[string][]Resolved{"b": {{Provenance: Provenance{Location: "b.json"}}}, "a": {{Provenance: Provenance{Location: "a.json"}}}},
	}
	if s.Empty() {
		t.Error("a set with documents is not empty")
	}
	// A component's own document comes first, which is what decides attribution on a tie.
	applied := s.For("a")
	if len(applied) != 2 || applied[0].Provenance.Location != "a.json" {
		t.Errorf("For(a) = %+v, want the component's own first", applied)
	}
	// Components in name order, so two runs of an unchanged descriptor report identically.
	docs := s.Documents()
	if len(docs) != 3 || docs[1].Provenance.Location != "a.json" || docs[2].Provenance.Location != "b.json" {
		t.Errorf("Documents() = %+v, want project first then components in name order", docs)
	}
}

func TestIndexCountAndTheEmptyLookup(t *testing.T) {
	ix := NewIndex([]Claim{{Vulnerability: "CVE-1", PURL: "pkg:x/y@1", Status: "not_affected"}})
	if ix.Count() != 1 {
		t.Errorf("Count() = %d, want 1", ix.Count())
	}
	// An unidentifiable finding matches nothing rather than everything.
	if _, _, ok := ix.Lookup("", "pkg:x/y@1"); ok {
		t.Error("a finding with no rule id must not match a claim")
	}
	var nilIndex *Index
	if _, _, ok := nilIndex.Lookup("CVE-1", ""); ok {
		t.Error("a nil index matches nothing")
	}
	if got := nilIndex.Unmatched(nil); got != nil {
		t.Errorf("nil index Unmatched = %+v, want nil", got)
	}
	if ix.Count() > 0 && len(ix.Unmatched(map[string]bool{})) != 1 {
		t.Error("a claim nothing used is unmatched")
	}
}

func TestAPURLWithNoTypeSegmentIsLeftAlone(t *testing.T) {
	// `pkg:` with nothing after it is not a package URL anybody can act on; it is returned as
	// written rather than reshaped into something that might collide with a real one.
	if got := normalizePURL("pkg:"); got != "pkg:" {
		t.Errorf("normalizePURL(pkg:) = %q, want it untouched", got)
	}
	if got := normalizePURL("   "); got != "" {
		t.Errorf("normalizePURL(blank) = %q, want empty", got)
	}
}
