package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// vexReporter renders an OpenVEX document: for each vulnerability this run saw, whether it
// affects the product, and on whose authority.
//
// An SBOM says what you ship and a scanner says which CVEs touch it. Neither answers the question
// a customer is actually asking, which is whether any of it matters — so they ask by email, once
// per customer, and someone answers the same question repeatedly from memory. A VEX document is
// that answer, written once, in a form their tooling can apply without a human reading it.
//
// Draugr can produce one almost entirely from what a run already knows, because a suppression
// here is not a delete. `reason`, `acceptedBy` and `expires` are required or recorded for
// governance reasons that have nothing to do with VEX, and they happen to be most of a VEX
// statement. What a suppression does *not* carry is the machine-readable claim — that is
// `vex.status`, and everything below is about not inventing it when it is absent.
//
// OpenVEX rather than CycloneDX VEX or CSAF: it is standalone, so it works whether or not SBOM
// generation is on; it is the smallest of the three; and Trivy and Grype both consume it, so a
// document is testable against a real reader rather than only against the schema.
type vexReporter struct{}

func (vexReporter) Format() string { return "vex" }

// openVEXContext is the spec version the documents claim. Pinned rather than tracking latest: a
// consumer resolves this IRI to decide how to read the document, so it changes when the mapping
// below has been checked against a new spec, not when one is published.
const openVEXContext = "https://openvex.dev/ns/v0.2.0"

// vexDocument is an OpenVEX document. Hand-modelled rather than taken from a library because the
// surface is this small, and because every field below has to be deterministic — the same run
// rendered twice is the same bytes, which is what lets a VEX document be committed, diffed and
// reviewed like the descriptor that produced it.
type vexDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Tooling    string         `json:"tooling,omitempty"`
	Statements []vexStatement `json:"statements"`
}

// vexStatement is one claim: this vulnerability, against this product, has this status.
type vexStatement struct {
	Vulnerability vexVulnerability `json:"vulnerability"`
	Products      []vexProduct     `json:"products"`
	Status        string           `json:"status"`
	// Justification is the machine-readable why, valid only with not_affected.
	Justification string `json:"justification,omitempty"`
	// ImpactStatement is the prose why, which VEX accepts in place of a justification for
	// not_affected. This is where an exclusion's `reason` lands when no vocabulary term was
	// declared.
	ImpactStatement string `json:"impact_statement,omitempty"`
	// ActionStatement is what is being done about an affected product. VEX requires one for
	// `affected`, and an accepted risk has exactly this to say.
	ActionStatement string `json:"action_statement,omitempty"`
	// StatusNotes carries what the governance record knows and VEX has no field for: who
	// accepted the risk and when their acceptance lapses.
	StatusNotes string `json:"status_notes,omitempty"`
}

type vexVulnerability struct {
	Name string `json:"name"`
}

type vexProduct struct {
	ID string `json:"@id"`
}

// vulnIDPattern decides which findings are vulnerabilities, and so which have anything to say in
// VEX. A secret in a config file and a misconfigured security group are real findings with no
// CVE to be un-affected by; putting them in a VEX document would be describing them as something
// they are not.
//
// Anchored and specific rather than "anything with a dash in it": the identifier goes into a
// document a stranger's tooling matches against, so a wrong one is worse than a missing one.
var vulnIDPattern = regexp.MustCompile(
	`^(CVE-\d{4}-\d{4,}` +
		`|GHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}` +
		`|OSV-\d{4}-\d+` +
		`|RUSTSEC-\d{4}-\d{4}` +
		`|GO-\d{4}-\d{4,})$`)

// vexStatusRank orders statuses by how much exposure they concede, least first. Used when one
// vulnerability is seen more than once in a run and the instances disagree: the strongest claim
// of exposure wins.
//
// The direction matters and is the whole safety argument for this format. Reporting `affected`
// for something that turns out to be `not_affected` costs a consumer some wasted triage.
// Reporting `not_affected` for something that is affected is telling a customer they are safe
// when they are not, and it is written down over your name.
var vexStatusRank = map[string]int{
	saga.VEXFixed:              0,
	saga.VEXNotAffected:        1,
	saga.VEXUnderInvestigation: 2,
	saga.VEXAffected:           3,
}

// Render writes the OpenVEX document for this run.
func (vexReporter) Render(w io.Writer, d Data) error {
	doc := buildVEX(d)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// buildVEX turns a run into a VEX document.
func buildVEX(d Data) vexDocument {
	byVuln := map[string]vexStatement{}
	controls := make([]string, 0, len(d.Run.Controls))
	for name := range d.Run.Controls {
		controls = append(controls, name)
	}
	sort.Strings(controls)
	for _, name := range controls {
		for _, res := range d.Run.Controls[name].Report.Results {
			if !vulnIDPattern.MatchString(res.RuleID) {
				continue
			}
			st := statementFor(res)
			// Keep the strongest claim of exposure when a CVE appears more than once — in two
			// components, or in two lockfiles of the same one. VEX statements are per product,
			// and this document has one product, so the instances have to resolve to a single
			// answer rather than contradict each other inside the same file.
			if prev, seen := byVuln[res.RuleID]; seen && vexStatusRank[prev.Status] >= vexStatusRank[st.Status] {
				continue
			}
			byVuln[res.RuleID] = st
		}
	}

	product := vexProduct{ID: vexProductID(d)}
	names := make([]string, 0, len(byVuln))
	for name := range byVuln {
		names = append(names, name)
	}
	sort.Strings(names)
	statements := make([]vexStatement, 0, len(names))
	for _, name := range names {
		st := byVuln[name]
		st.Vulnerability = vexVulnerability{Name: name}
		st.Products = []vexProduct{product}
		statements = append(statements, st)
	}

	doc := vexDocument{
		Context:    openVEXContext,
		Author:     vexAuthor(d),
		Timestamp:  d.Generated.UTC().Format(time.RFC3339),
		Version:    1,
		Statements: statements,
	}
	if d.Version != "" {
		doc.Tooling = "draugr/" + d.Version
	}
	doc.ID = vexID(doc)
	return doc
}

// statementFor maps one finding to its VEX status.
//
// The mapping is conservative by construction, because the only inputs that could make it less so
// are free text. An untriaged finding is `under_investigation` — true, and the one status that
// commits to nothing. A suppression that declared no VEX status becomes `affected`: a decision
// was made, so "under investigation" would be false, and `not_affected` would be a claim of
// safety inferred from prose. Reading the reason to guess which one was meant is exactly the
// inference this codebase keeps out of anything reproducible.
func statementFor(res sarif.Result) vexStatement {
	sup := res.Suppression
	if sup == nil {
		return vexStatement{Status: saga.VEXUnderInvestigation}
	}
	st := vexStatement{StatusNotes: vexStatusNotes(sup)}
	switch sup.VEXStatus {
	case saga.VEXNotAffected:
		st.Status = saga.VEXNotAffected
		// VEX wants one of the two, and prefers the vocabulary term. The reason is prose written
		// for a reviewer, which is precisely what impact_statement is for.
		if sup.VEXJustification != "" {
			st.Justification = sup.VEXJustification
		} else {
			st.ImpactStatement = sup.Justification
		}
	case saga.VEXFixed:
		st.Status = saga.VEXFixed
	default:
		st.Status = saga.VEXAffected
		st.ActionStatement = sup.Justification
	}
	return st
}

// vexStatusNotes carries the governance half of a suppression — who accepted it and when it
// lapses. VEX has no field for either, and dropping them would throw away the part of the record
// an auditor asks about first.
func vexStatusNotes(sup *sarif.Suppression) string {
	switch {
	case sup.AcceptedBy != "" && sup.Expires != "":
		return fmt.Sprintf("accepted by %s; expires %s", sup.AcceptedBy, sup.Expires)
	case sup.AcceptedBy != "":
		return "accepted by " + sup.AcceptedBy
	case sup.Expires != "":
		return "expires " + sup.Expires
	}
	return ""
}

// vexAuthor is who these statements are attributed to.
//
// Falls back to the release name so a document can be produced without configuration, and the
// reference says plainly that a project name is not a party. Naming Draugr here instead would be
// worse than a weak answer: we did not decide any of this, and a document asserting that the tool
// vouches for a customer's product is false in a way nobody would catch.
func vexAuthor(d Data) string {
	if d.VEX != nil && d.VEX.Author != "" {
		return d.VEX.Author
	}
	return d.Release.Name
}

// vexProductID is the identifier the statements are about.
//
// Defaults to a purl over the release, because the release *is* the product — VEX is asked for
// per shipped thing, not per repository. `pkg:generic/` is honest about being synthesised from
// the descriptor rather than taken from anywhere real, and config.vex.product replaces it with
// whatever a consumer's SBOM calls this.
//
// A configured purl carrying no version gets the release's appended. That is what keeps the
// identifier from going stale: a VEX statement is about a *version* of a product — a
// not_affected that held in 2.3 says nothing about 2.4 — so a product string with the version
// written into it silently keeps claiming the old one after the release moves on. Writing
// `pkg:oci/acme/api` and letting the release supply the version cannot drift.
//
// A version that *is* written is left exactly as given. Pinning to a digest is a better practice
// than pinning to a tag, and a digest belongs in that position; overriding it would be Draugr
// deciding it knows the artifact better than the person who named it.
func vexProductID(d Data) string {
	if d.VEX != nil && d.VEX.Product != "" {
		return withReleaseVersion(d.VEX.Product, d.Release.Version)
	}
	id := "pkg:generic/" + d.Release.Name
	if d.Release.Version != "" {
		id += "@" + d.Release.Version
	}
	return id
}

// withReleaseVersion appends the release's version to a package URL that does not carry one.
//
// Only package URLs. VEX identifies a product by IRI and a purl is merely the conventional
// choice, so a product named by a plain URL is left alone — appending "@2.4.0" to
// `https://acme.example/products/api` would produce something that is neither the IRI given nor
// a valid anything else.
func withReleaseVersion(product, version string) string {
	if version == "" || !strings.HasPrefix(product, "pkg:") {
		return product
	}
	// A purl is pkg:type/namespace/name@version?qualifiers#subpath. Version, when present,
	// precedes the qualifiers and the subpath, so those are trimmed before looking for it.
	head := product
	if i := strings.IndexAny(head, "?#"); i >= 0 {
		head = head[:i]
	}
	if strings.Contains(strings.TrimPrefix(head, "pkg:"), "@") {
		return product // already versioned — deliberately, including a digest
	}
	return head + "@" + version + product[len(head):]
}

// vexID is the document's identifier: a digest of its own content.
//
// OpenVEX requires a unique IRI and suggests exactly this. Deriving it from the content rather
// than from a clock or a counter means re-rendering the same run gives the same document, so a
// VEX file can live in version control and a diff shows a decision changing rather than the file
// being regenerated.
func vexID(doc vexDocument) string {
	h := sha256.New()
	// A hash.Hash never returns an error, which is why the writes below are not checked.
	add := func(parts ...any) { _, _ = fmt.Fprintln(h, parts...) }
	add(doc.Author, doc.Timestamp, doc.Version)
	for _, s := range doc.Statements {
		for _, p := range s.Products {
			add(s.Vulnerability.Name, p.ID, s.Status,
				s.Justification, s.ImpactStatement, s.ActionStatement, s.StatusNotes)
		}
	}
	return "https://openvex.dev/docs/draugr/" + hex.EncodeToString(h.Sum(nil))
}
