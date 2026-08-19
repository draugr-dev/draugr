// Package vex reads OpenVEX documents somebody else wrote.
//
// Draugr has produced VEX since it could suppress a finding (`pkg/report`, `--report vex`). This
// is the other direction: a supplier ships a component and a document saying which of its CVEs do
// not affect it, and until now the only way to act on that was to retype their analysis into
// `config.exclude` as though you had decided it. That loses the answer to the question the whole
// suppression model exists to answer — who decided this was acceptable, and when.
//
// Reading is a separate package from writing on purpose. The writer builds a document out of a
// run and owes the reader determinism; this reads a document a stranger produced and owes the run
// suspicion. Sharing a struct between them would make every field both a promise and an
// assumption.
//
// OpenVEX only, to start. It is what Draugr already emits, what Trivy and Grype already read, and
// the smallest of the three formats — so a document can be tested against a real consumer rather
// than only against a schema. CSAF and CycloneDX VEX carry the same statements in more envelope.
package vex

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// Document is an OpenVEX document as read from disk.
//
// Only the fields Draugr acts on or attributes are modeled. An unknown field is ignored rather
// than rejected: this is somebody else's document, and refusing to read one because it carries a
// field a later spec added would make Draugr the reason a supplier's claim went unheard.
type Document struct {
	// Context is the spec IRI the document claims, e.g. https://openvex.dev/ns/v0.2.0.
	Context string `json:"@context"`
	// ID identifies this document. Reported so a reader can tell two revisions apart.
	ID string `json:"@id"`
	// Author is who is making these statements. The single most important field here: a VEX
	// statement's weight is entirely a function of who signed it, and a document that does not
	// say is one a reader has to be told about rather than quietly obeyed.
	Author string `json:"author"`
	// Timestamp is when the document was made. A supplier's claim is made at a time they chose,
	// not when you scanned, so the report shows its age rather than presenting it as fresh.
	Timestamp string `json:"timestamp"`
	// Version increments as a document is revised.
	Version int `json:"version"`
	// Statements are the claims themselves.
	Statements []Statement `json:"statements"`
}

// Statement is one claim: this vulnerability, against these products, has this status.
type Statement struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	// Products are what the statement is about — the supplier's own artifact.
	Products []Product `json:"products"`
	// Status is the claim: not_affected, affected, fixed or under_investigation.
	Status string `json:"status"`
	// Justification is the machine-readable why, from VEX's fixed vocabulary, valid only with
	// not_affected.
	Justification string `json:"justification,omitempty"`
	// ImpactStatement is the prose why, which VEX accepts in place of a justification.
	ImpactStatement string `json:"impact_statement,omitempty"`
	// ActionStatement is what is being done about an affected product.
	ActionStatement string `json:"action_statement,omitempty"`
	// StatusNotes is free text the producer attached to the status.
	StatusNotes string `json:"status_notes,omitempty"`
	// Timestamp overrides the document's, when a single statement was revised on its own.
	Timestamp string `json:"timestamp,omitempty"`
}

// Vulnerability names the flaw a statement is about.
//
// OpenVEX 0.2.0 made this an object with a `name`; 0.1.0 had a bare string. Both are accepted,
// because a document written against the older spec is not wrong, it is old — and a supplier who
// has not revised their tooling is exactly the supplier whose claims are hardest to get hold of.
type Vulnerability struct {
	Name string `json:"name"`
}

// UnmarshalJSON accepts both the object form and the bare string of OpenVEX 0.1.0.
func (v *Vulnerability) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		v.Name = name
		return nil
	}
	// The alias avoids recursing into this method.
	type plain Vulnerability
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("vulnerability is neither a name nor an object: %w", err)
	}
	*v = Vulnerability(p)
	return nil
}

// Product is a thing a statement is about, identified by an IRI — conventionally a package URL.
//
// Subcomponents are the half that does the work here. A supplier says "our product is not
// affected by CVE-X, which is in libfoo", and libfoo is what a scan of their image actually
// found. Matching only on the product would miss every such statement, which is most of them.
type Product struct {
	ID            string         `json:"@id"`
	Subcomponents []Subcomponent `json:"subcomponents,omitempty"`
}

// Subcomponent is a component inside a product, identified the same way.
type Subcomponent struct {
	ID string `json:"@id"`
}

// Load reads an OpenVEX document from a file.
func Load(path string) (Document, error) {
	f, err := os.Open(path) // #nosec G304 -- a descriptor-supplied path, like every other input
	if err != nil {
		return Document{}, err
	}
	defer func() { _ = f.Close() }()
	doc, err := Read(f)
	if err != nil {
		return Document{}, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

// Read parses an OpenVEX document.
//
// What it refuses is a document that cannot be acted on: unparseable JSON, or one whose
// statements carry no status. Everything else is read and reported, because the alternative to a
// weak document is not a strong one — it is no supplier analysis at all, and the report is where
// its weakness should be visible.
func Read(r io.Reader) (Document, error) {
	var doc Document
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("not a readable OpenVEX document: %w", err)
	}
	if len(doc.Statements) == 0 {
		return Document{}, fmt.Errorf("document carries no statements")
	}
	for i, st := range doc.Statements {
		if st.Status == "" {
			return Document{}, fmt.Errorf("statement %d has no status", i+1)
		}
		if !validStatus(st.Status) {
			return Document{}, fmt.Errorf("statement %d has status %q, which is not one of %s",
				i+1, st.Status, strings.Join(Statuses, ", "))
		}
	}
	return doc, nil
}

// Statuses are the four OpenVEX statuses. Unlike saga.VEXStatuses — which lists what one of *our*
// exclusions may declare — every one of these is readable, including under_investigation, because
// a supplier saying "we are still looking" is a real and useful thing to be told.
var Statuses = []string{
	saga.VEXNotAffected,
	saga.VEXAffected,
	saga.VEXFixed,
	saga.VEXUnderInvestigation,
}

func validStatus(s string) bool { return slices.Contains(Statuses, s) }

// Suppresses reports whether a status excuses a finding.
//
// Only not_affected and fixed do. `affected` and `under_investigation` concede exposure rather
// than excusing it — a supplier telling you that you *are* affected must never be the reason a
// finding stops being counted, which is what treating every statement alike would do.
func Suppresses(status string) bool {
	return status == saga.VEXNotAffected || status == saga.VEXFixed
}

// Age is how old the document's timestamp is, and whether it could be read at all.
//
// Reported rather than enforced. How stale is too stale depends on the supplier and the
// component, and a tool that silently stopped honoring a claim on a date of its own choosing
// would be making that decision for the operator without telling them.
func (d Document) Age(now time.Time) (time.Duration, bool) {
	if d.Timestamp == "" {
		return 0, false
	}
	when, err := time.Parse(time.RFC3339, d.Timestamp)
	if err != nil {
		return 0, false
	}
	return now.Sub(when), true
}
