package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// vexData builds a run with the given results under one control.
func vexData(results ...sarif.Result) Data {
	return Data{
		Release:   saga.Release{Name: "acme-api", Version: "2.4.0"},
		Generated: time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC),
		Version:   "0.68.0",
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"sca": {Report: sarif.Report{Results: results}},
		}},
	}
}

func vexResult(ruleID string, sup *sarif.Suppression) sarif.Result {
	return sarif.Result{RuleID: ruleID, Level: sarif.LevelError, Message: ruleID, Suppression: sup}
}

func TestVEXDocumentEnvelope(t *testing.T) {
	doc := buildVEX(vexData(vexResult("CVE-2024-0001", nil)))

	if doc.Context != openVEXContext {
		t.Errorf("@context = %q, want %q", doc.Context, openVEXContext)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if doc.Timestamp != "2026-08-05T10:00:00Z" {
		t.Errorf("timestamp = %q", doc.Timestamp)
	}
	if doc.Tooling != "draugr/0.68.0" {
		t.Errorf("tooling = %q", doc.Tooling)
	}
	if !strings.HasPrefix(doc.ID, "https://openvex.dev/docs/draugr/") {
		t.Errorf("@id = %q, want a resolvable IRI", doc.ID)
	}
}

// An untriaged finding is the one case where nothing has been decided, and under_investigation is
// the only status that says so without claiming anything.
func TestVEXUntriagedFindingIsUnderInvestigation(t *testing.T) {
	doc := buildVEX(vexData(vexResult("CVE-2024-0001", nil)))
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(doc.Statements))
	}
	if got := doc.Statements[0].Status; got != saga.VEXUnderInvestigation {
		t.Errorf("status = %q, want %q", got, saga.VEXUnderInvestigation)
	}
}

// The safety property of the whole format: a suppression that did not declare a VEX status must
// never become not_affected. Guessing from the reason would be telling a consumer they are safe
// on the strength of prose nobody promised was about reachability.
func TestVEXUndeclaredSuppressionIsAffectedNotNotAffected(t *testing.T) {
	doc := buildVEX(vexData(vexResult("CVE-2024-0001", &sarif.Suppression{
		Kind:          "external",
		Justification: "Not reachable in our configuration.",
		AcceptedBy:    "sec@acme.example",
		Expires:       "2026-12-31",
	})))

	st := doc.Statements[0]
	if st.Status != saga.VEXAffected {
		t.Fatalf("status = %q, want %q — an undeclared suppression must not claim safety", st.Status, saga.VEXAffected)
	}
	if st.ActionStatement != "Not reachable in our configuration." {
		t.Errorf("action_statement = %q, want the exclusion's reason", st.ActionStatement)
	}
	if st.Justification != "" || st.ImpactStatement != "" {
		t.Errorf("affected must carry neither justification nor impact_statement, got %q / %q",
			st.Justification, st.ImpactStatement)
	}
	if want := "accepted by sec@acme.example; expires 2026-12-31"; st.StatusNotes != want {
		t.Errorf("status_notes = %q, want %q", st.StatusNotes, want)
	}
}

func TestVEXDeclaredNotAffectedUsesTheVocabulary(t *testing.T) {
	doc := buildVEX(vexData(vexResult("CVE-2024-0001", &sarif.Suppression{
		Kind:             "external",
		Justification:    "The redirect path is never taken.",
		VEXStatus:        saga.VEXNotAffected,
		VEXJustification: "vulnerable_code_not_in_execute_path",
	})))

	st := doc.Statements[0]
	if st.Status != saga.VEXNotAffected {
		t.Errorf("status = %q", st.Status)
	}
	if st.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("justification = %q", st.Justification)
	}
	// VEX takes one or the other; sending both would be redundant and the vocabulary is the half
	// a consumer can act on.
	if st.ImpactStatement != "" {
		t.Errorf("impact_statement = %q, want empty when a vocabulary term was given", st.ImpactStatement)
	}
}

// not_affected requires a justification or a prose statement. Without a vocabulary term the
// exclusion's reason has to carry it, or the document is invalid.
func TestVEXNotAffectedWithoutAVocabularyTermFallsBackToProse(t *testing.T) {
	doc := buildVEX(vexData(vexResult("CVE-2024-0001", &sarif.Suppression{
		Kind:          "external",
		Justification: "Ships disabled; the module is never loaded.",
		VEXStatus:     saga.VEXNotAffected,
	})))

	st := doc.Statements[0]
	if st.ImpactStatement != "Ships disabled; the module is never loaded." {
		t.Errorf("impact_statement = %q", st.ImpactStatement)
	}
	if st.Justification != "" {
		t.Errorf("justification = %q, want empty", st.Justification)
	}
}

func TestVEXFixedStatus(t *testing.T) {
	doc := buildVEX(vexData(vexResult("CVE-2024-0001", &sarif.Suppression{
		Kind: "external", Justification: "Patched in 2.4.0.", VEXStatus: saga.VEXFixed,
	})))
	if got := doc.Statements[0].Status; got != saga.VEXFixed {
		t.Errorf("status = %q, want %q", got, saga.VEXFixed)
	}
}

// A VEX document about a product cannot say two things about one CVE, so instances have to
// resolve — and they resolve toward exposure, never away from it.
func TestVEXConflictingInstancesResolveToTheStrongestClaim(t *testing.T) {
	notAffected := &sarif.Suppression{
		Kind: "external", Justification: "not used here", VEXStatus: saga.VEXNotAffected,
	}
	for _, tc := range []struct {
		name string
		a, b sarif.Result
		want string
	}{
		{"untriaged beats not_affected",
			vexResult("CVE-2024-0001", notAffected), vexResult("CVE-2024-0001", nil),
			saga.VEXUnderInvestigation},
		{"affected beats untriaged",
			vexResult("CVE-2024-0001", nil),
			vexResult("CVE-2024-0001", &sarif.Suppression{Kind: "external", Justification: "accepted"}),
			saga.VEXAffected},
		{"not_affected beats fixed",
			vexResult("CVE-2024-0001", &sarif.Suppression{Kind: "external", Justification: "p", VEXStatus: saga.VEXFixed}),
			vexResult("CVE-2024-0001", notAffected),
			saga.VEXNotAffected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := buildVEX(vexData(tc.a, tc.b))
			if len(doc.Statements) != 1 {
				t.Fatalf("statements = %d, want 1 — one CVE is one statement", len(doc.Statements))
			}
			if got := doc.Statements[0].Status; got != tc.want {
				t.Errorf("status = %q, want %q", got, tc.want)
			}
			// Order of arrival must not decide it.
			rev := buildVEX(vexData(tc.b, tc.a))
			if rev.Statements[0].Status != tc.want {
				t.Errorf("reversed order gave %q, want %q", rev.Statements[0].Status, tc.want)
			}
		})
	}
}

// VEX is about vulnerabilities. A hardcoded secret is a real finding with no CVE to be unaffected
// by, and describing it as one would misrepresent it to every consumer of the document.
func TestVEXOnlyVulnerabilityFindingsBecomeStatements(t *testing.T) {
	for _, id := range []string{
		"generic-api-key", "AVD-AWS-0107", "python.lang.security.audit.eval-detected",
		"license/GPL-3.0-only/github.com/x/y", "CVE-24-1", "GHSA-short",
	} {
		doc := buildVEX(vexData(vexResult(id, nil)))
		if len(doc.Statements) != 0 {
			t.Errorf("%q produced a statement; it is not a vulnerability identifier", id)
		}
	}
	for _, id := range []string{
		"CVE-2024-0001", "CVE-2024-12345", "GHSA-jfh8-c2jp-5v3q",
		"OSV-2023-1", "RUSTSEC-2021-0079", "GO-2024-1234",
	} {
		doc := buildVEX(vexData(vexResult(id, nil)))
		if len(doc.Statements) != 1 {
			t.Errorf("%q produced no statement; it is a vulnerability identifier", id)
		}
	}
}

func TestVEXProductAndAuthorDefaultToTheRelease(t *testing.T) {
	doc := buildVEX(vexData(vexResult("CVE-2024-0001", nil)))
	if doc.Author != "acme-api" {
		t.Errorf("author = %q, want the release name", doc.Author)
	}
	if got := doc.Statements[0].Products[0].ID; got != "pkg:generic/acme-api@2.4.0" {
		t.Errorf("product = %q", got)
	}
}

func TestVEXConfigOverridesAuthorAndProduct(t *testing.T) {
	d := vexData(vexResult("CVE-2024-0001", nil))
	d.VEX = &saga.VEXConfig{Author: "Acme Ltd <sec@acme.example>", Product: "pkg:oci/acme/api@2.4.0"}
	doc := buildVEX(d)
	if doc.Author != "Acme Ltd <sec@acme.example>" {
		t.Errorf("author = %q", doc.Author)
	}
	if got := doc.Statements[0].Products[0].ID; got != "pkg:oci/acme/api@2.4.0" {
		t.Errorf("product = %q", got)
	}
}

// A release with no version must not produce a purl ending in a bare "@".
func TestVEXProductOmitsAnEmptyVersion(t *testing.T) {
	d := vexData(vexResult("CVE-2024-0001", nil))
	d.Release = saga.Release{Name: "acme-api"}
	if got := buildVEX(d).Statements[0].Products[0].ID; got != "pkg:generic/acme-api" {
		t.Errorf("product = %q", got)
	}
}

// A VEX file belongs in version control, which only works if re-rendering an unchanged run gives
// unchanged bytes — otherwise every regeneration is a diff and nobody reads them.
func TestVEXRenderIsDeterministic(t *testing.T) {
	d := vexData(
		vexResult("CVE-2024-0002", nil),
		vexResult("CVE-2024-0001", &sarif.Suppression{Kind: "external", Justification: "x"}),
		vexResult("CVE-2024-0003", nil),
	)
	var a, b bytes.Buffer
	for _, w := range []*bytes.Buffer{&a, &b} {
		if err := (vexReporter{}).Render(w, d); err != nil {
			t.Fatalf("Render: %v", err)
		}
	}
	if a.String() != b.String() {
		t.Error("two renders of the same run differ")
	}
	var doc vexDocument
	if err := json.Unmarshal(a.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for i := 1; i < len(doc.Statements); i++ {
		if doc.Statements[i-1].Vulnerability.Name > doc.Statements[i].Vulnerability.Name {
			t.Errorf("statements are not sorted: %q before %q",
				doc.Statements[i-1].Vulnerability.Name, doc.Statements[i].Vulnerability.Name)
		}
	}
}

// Changing a decision has to change the document's identity, or a consumer caching by @id serves
// the superseded claims.
func TestVEXIDTracksContent(t *testing.T) {
	base := buildVEX(vexData(vexResult("CVE-2024-0001", nil)))
	changed := buildVEX(vexData(vexResult("CVE-2024-0001", &sarif.Suppression{
		Kind: "external", Justification: "accepted", VEXStatus: saga.VEXNotAffected,
	})))
	if base.ID == changed.ID {
		t.Error("@id unchanged after the status changed")
	}
}

// A scan that found no vulnerabilities still has to produce a document a consumer can parse.
func TestVEXWithNoVulnerabilitiesIsStillAValidDocument(t *testing.T) {
	var buf bytes.Buffer
	if err := (vexReporter{}).Render(&buf, vexData()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if got, ok := doc["statements"].([]any); !ok || len(got) != 0 {
		t.Errorf("statements = %v, want an empty array rather than null", doc["statements"])
	}
}

func TestVEXIsRegisteredAndNamed(t *testing.T) {
	if _, err := For("vex"); err != nil {
		t.Fatalf("For(vex): %v", err)
	}
	if got := Filename("vex"); got != "openvex.json" {
		t.Errorf("Filename(vex) = %q", got)
	}
	if err := StreamFormat("vex"); err != nil {
		t.Errorf("StreamFormat(vex): %v", err)
	}
}

// A VEX statement is about a *version* of a product, so a product string with the version baked
// into it keeps claiming the old one after the release moves on — silently, in a signed
// document. A purl that omits the version cannot drift.
func TestVEXProductTracksTheReleaseVersion(t *testing.T) {
	d := vexData(vexResult("CVE-2024-0001", nil))
	d.VEX = &saga.VEXConfig{Product: "pkg:oci/acme/api"}
	if got := buildVEX(d).Statements[0].Products[0].ID; got != "pkg:oci/acme/api@2.4.0" {
		t.Errorf("product = %q, want the release's version appended", got)
	}
}

// A version somebody wrote is a decision, not an oversight — pinning to a digest is better
// practice than pinning to a tag, and it lives in exactly that position.
func TestVEXProductKeepsAnExplicitVersion(t *testing.T) {
	for _, pinned := range []string{
		"pkg:oci/acme/api@1.0.0",
		"pkg:oci/acme/api@sha256:0123456789abcdef",
	} {
		d := vexData(vexResult("CVE-2024-0001", nil))
		d.VEX = &saga.VEXConfig{Product: pinned}
		if got := buildVEX(d).Statements[0].Products[0].ID; got != pinned {
			t.Errorf("product = %q, want %q left alone", got, pinned)
		}
	}
}

// The version belongs before the qualifiers and subpath, which is where the purl spec puts it.
func TestVEXProductInsertsTheVersionBeforeQualifiers(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"pkg:oci/acme/api?repository_url=acme.azurecr.io",
			"pkg:oci/acme/api@2.4.0?repository_url=acme.azurecr.io"},
		{"pkg:golang/github.com/acme/api#cmd/api",
			"pkg:golang/github.com/acme/api@2.4.0#cmd/api"},
	} {
		d := vexData(vexResult("CVE-2024-0001", nil))
		d.VEX = &saga.VEXConfig{Product: tc.in}
		if got := buildVEX(d).Statements[0].Products[0].ID; got != tc.want {
			t.Errorf("product = %q, want %q", got, tc.want)
		}
	}
}

// VEX identifies a product by IRI; a purl is only the conventional choice. Appending a version to
// something that is not a purl would produce neither the IRI given nor a valid anything else.
func TestVEXProductLeavesANonPurlAlone(t *testing.T) {
	d := vexData(vexResult("CVE-2024-0001", nil))
	d.VEX = &saga.VEXConfig{Product: "https://acme.example/products/api"}
	if got := buildVEX(d).Statements[0].Products[0].ID; got != "https://acme.example/products/api" {
		t.Errorf("product = %q, want it untouched", got)
	}
}
