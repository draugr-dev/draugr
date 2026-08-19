package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/vex"
)

// claimDoc builds a document asserting one status about one package.
func claimDoc(author, cve, purl, status string) vex.Document {
	return vex.Document{
		Author:    author,
		Timestamp: "2026-08-01T09:00:00Z",
		Statements: []vex.Statement{{
			Vulnerability:   vex.Vulnerability{Name: cve},
			Products:        []vex.Product{{ID: "pkg:oci/product", Subcomponents: []vex.Subcomponent{{ID: purl}}}},
			Status:          status,
			ImpactStatement: "not reachable in our build",
		}},
	}
}

func resolved(author, cve, purl, status, location string) vex.Resolved {
	return vex.Resolved{
		Document:   claimDoc(author, cve, purl, status),
		Provenance: vex.Provenance{Kind: "path", Location: location, Author: author, Statements: 1},
	}
}

// finding builds one result attributed to a component and a package.
func finding(component, cve, purl string) sarif.Result {
	return sarif.Result{
		RuleID:    cve,
		Level:     sarif.LevelError,
		Component: component,
		Package:   &sarif.Package{Name: "p", PURL: purl},
	}
}

// The whole point: the supplier's analysis is applied, and the record says it was theirs rather
// than a decision this project made and is answerable for.
func TestASuppliersClaimSuppressesAndSaysWhose(t *testing.T) {
	controls := controlsWith(finding("api", "CVE-1", "pkg:pypi/flask@0.12.2"))
	set := vex.Set{ByComponent: map[string][]vex.Resolved{
		"api": {resolved("Acme Ltd", "CVE-1", "pkg:pypi/flask@0.12.2", "not_affected", "vendor/acme.json")},
	}}

	n, docs, unmatched := applyVEX(controls, set)
	if n != 1 {
		t.Fatalf("imported = %d, want 1", n)
	}
	res := controls["sca"].Report.Results[0]
	if !res.Suppressed() {
		t.Fatal("the finding should be suppressed")
	}
	if !res.Imported() {
		t.Error("the suppression must be marked as coming from outside this project")
	}
	if res.Suppression.Author != "Acme Ltd" {
		t.Errorf("author = %q, want the document's", res.Suppression.Author)
	}
	if res.Suppression.AcceptedBy != "" {
		t.Error("acceptedBy is for a decision this project made, and must stay empty here")
	}
	if res.Suppression.Asserted == "" {
		t.Error("a claim's own date is what makes a stale one visible")
	}
	if len(unmatched) != 0 {
		t.Errorf("unmatched = %+v, want none", unmatched)
	}
	if len(docs) != 1 || docs[0].Provenance.Applied != 1 {
		t.Errorf("provenance = %+v, want one document credited with one finding", docs)
	}
}

// The standing rule for anything keyed per component, and the failure that would turn one
// vendor's assurance into a silent suppression somewhere nobody was looking.
func TestOneSuppliersClaimDoesNotReachAnotherComponent(t *testing.T) {
	controls := controlsWith(
		finding("api", "CVE-1", "pkg:pypi/flask@0.12.2"),
		finding("worker", "CVE-1", "pkg:pypi/flask@0.12.2"),
	)
	set := vex.Set{ByComponent: map[string][]vex.Resolved{
		"api": {resolved("Acme Ltd", "CVE-1", "pkg:pypi/flask@0.12.2", "not_affected", "vendor/acme.json")},
	}}

	n, _, _ := applyVEX(controls, set)
	if n != 1 {
		t.Fatalf("imported = %d, want 1 — only the component that declared the source", n)
	}
	for _, res := range controls["sca"].Report.Results {
		switch res.Component {
		case "api":
			if !res.Suppressed() {
				t.Error("api declared the source and its finding should be excused")
			}
		case "worker":
			if res.Suppressed() {
				t.Error("worker declared nothing — another component's supplier must not excuse its findings")
			}
		}
	}
}

// A project-wide source is the internal-supply-chain case: one platform document, many consumers.
func TestAProjectWideClaimReachesEveryComponent(t *testing.T) {
	controls := controlsWith(
		finding("api", "CVE-1", "pkg:pypi/flask@0.12.2"),
		finding("worker", "CVE-1", "pkg:pypi/flask@0.12.2"),
	)
	set := vex.Set{Project: []vex.Resolved{
		resolved("Platform Team", "CVE-1", "pkg:pypi/flask@0.12.2", "not_affected", "platform.json"),
	}}

	n, _, _ := applyVEX(controls, set)
	if n != 2 {
		t.Fatalf("imported = %d, want 2 — a project-wide document applies to every component", n)
	}
}

// A supplier telling you that you *are* affected must never be the reason a finding stops being
// counted. It is still recorded as matched, so the supplier is not told their statement was ignored.
func TestAnAffectedClaimChangesNothingAndIsNotReportedUnmatched(t *testing.T) {
	controls := controlsWith(finding("api", "CVE-1", "pkg:pypi/flask@0.12.2"))
	set := vex.Set{ByComponent: map[string][]vex.Resolved{
		"api": {resolved("Acme Ltd", "CVE-1", "pkg:pypi/flask@0.12.2", "affected", "vendor/acme.json")},
	}}

	n, _, unmatched := applyVEX(controls, set)
	if n != 0 {
		t.Errorf("imported = %d, want 0 — affected concedes exposure", n)
	}
	if controls["sca"].Report.Results[0].Suppressed() {
		t.Error("an affected claim must not suppress")
	}
	if len(unmatched) != 0 {
		t.Errorf("unmatched = %+v — the claim matched a finding and was acted on", unmatched)
	}
}

// This project's own decision stands. A supplier's claim is additional evidence, not an override:
// where both have something to say, the local reason is the one whose author can be asked.
func TestALocalDecisionIsNotOverwrittenByASupplier(t *testing.T) {
	res := finding("api", "CVE-1", "pkg:pypi/flask@0.12.2")
	res.Suppression = &sarif.Suppression{
		Kind: "external", Justification: "we accepted this", AcceptedBy: "A. Engineer",
	}
	controls := controlsWith(res)
	set := vex.Set{ByComponent: map[string][]vex.Resolved{
		"api": {resolved("Acme Ltd", "CVE-1", "pkg:pypi/flask@0.12.2", "not_affected", "vendor/acme.json")},
	}}

	n, _, _ := applyVEX(controls, set)
	if n != 0 {
		t.Errorf("imported = %d, want 0 — the local decision already covered it", n)
	}
	got := controls["sca"].Report.Results[0].Suppression
	if got.AcceptedBy != "A. Engineer" || got.Origin == sarif.OriginVEX {
		t.Errorf("suppression = %+v, want this project's own reason intact", got)
	}
}

// A statement matching nothing is reported, because it looks exactly like one that worked.
func TestAClaimThatMatchesNothingIsReported(t *testing.T) {
	controls := controlsWith(finding("api", "CVE-1", "pkg:pypi/flask@0.12.2"))
	set := vex.Set{ByComponent: map[string][]vex.Resolved{
		"api": {resolved("Acme Ltd", "CVE-999", "pkg:pypi/other@1.0", "not_affected", "vendor/acme.json")},
	}}

	n, docs, unmatched := applyVEX(controls, set)
	if n != 0 {
		t.Fatalf("imported = %d, want 0", n)
	}
	if len(unmatched) != 1 || unmatched[0].Vulnerability != "CVE-999" {
		t.Fatalf("unmatched = %+v, want the statement nothing matched", unmatched)
	}
	// And the document is still reported, credited with nothing — a document that excused nothing
	// is otherwise indistinguishable from one that was never configured.
	if len(docs) != 1 || docs[0].Provenance.Applied != 0 {
		t.Errorf("provenance = %+v, want the document present and credited with 0", docs)
	}
}

func TestNoSourcesChangesNothing(t *testing.T) {
	controls := controlsWith(finding("api", "CVE-1", "pkg:pypi/flask@0.12.2"))
	n, docs, unmatched := applyVEX(controls, vex.Set{})
	if n != 0 || docs != nil || unmatched != nil {
		t.Errorf("applyVEX with no sources = (%d, %+v, %+v), want it inert", n, docs, unmatched)
	}
	if controls["sca"].Report.Results[0].Suppressed() {
		t.Error("nothing was configured and nothing should be suppressed")
	}
}
