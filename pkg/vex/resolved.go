package vex

import (
	"sort"
	"time"
)

// Provenance is where a document came from and what it was when it was read.
//
// Recorded because a supplier's VEX is a claim made at a time they chose, not a scan Draugr
// performed. Every other input to a run can be re-read to reproduce a verdict; this one cannot,
// because the URL may serve something else tomorrow and the branch may have moved. So the report
// carries enough to say what was actually applied — where it came from, what it hashed to, and
// how old the claim was — and a reader who disagrees can check rather than take it on trust.
type Provenance struct {
	// Kind is how the document was reached: "path", "url" or "repository".
	Kind string
	// Location is the path, URL, or `repository#path` as the descriptor named it.
	Location string
	// Revision is the commit a repository source actually read. Empty for the others.
	//
	// Resolved even when the descriptor named a branch, which is the point: a ref that moves
	// makes a run unreproducible unless the commit it resolved to is written down.
	Revision string
	// Digest is the sha256 of the bytes read, so two runs can be compared without the document.
	Digest string
	// ReadAt is when Draugr read it — distinct from the document's own timestamp, and the pair is
	// what tells a reader whether they are looking at a fresh copy of a stale claim.
	ReadAt time.Time
	// Author is the document's author, carried up so the report can attribute without reparsing.
	Author string
	// Timestamp is the document's own, as written.
	Timestamp string
	// Statements is how many claims the document carried.
	Statements int
	// Applied is how many of them matched a finding. Zero against a non-zero Statements is worth
	// seeing: a document that excused nothing is indistinguishable from one that was never read,
	// and usually means the supplier and the scanner name packages differently.
	Applied int
}

// Resolved is a document together with where it came from.
type Resolved struct {
	Document   Document
	Provenance Provenance
}

// Set is every supplier document a run has, sorted by what it applies to.
//
// Project holds documents that apply to every component; ByComponent holds those a component
// declared for itself. Kept apart rather than flattened at load, because "who declared this"
// survives into the report — a claim applied project-wide and one a component asked for are the
// same statement with different blast radius, and an operator reviewing a suppression wants to
// know which.
type Set struct {
	Project     []Resolved
	ByComponent map[string][]Resolved
}

// Empty reports whether there is nothing to apply.
func (s Set) Empty() bool { return len(s.Project) == 0 && len(s.ByComponent) == 0 }

// For returns the documents that apply to one component, the component's own first.
//
// Its own first because NewIndex keeps the first of two claims that concede equal exposure, so
// this is what decides attribution when a project-wide document and a component's own say the
// same thing: the credit goes to the one somebody chose for this component. Where the two
// genuinely disagree the stronger claim still wins, whatever the order.
func (s Set) For(component string) []Resolved {
	own := s.ByComponent[component]
	out := make([]Resolved, 0, len(s.Project)+len(own))
	out = append(out, own...)
	out = append(out, s.Project...)
	return out
}

// Documents returns every resolved document once, for reporting provenance.
//
// Components in name order rather than map order. Go randomizes map iteration, so without this
// the provenance block — and the report.json that carries it — would come out differently on two
// runs of an unchanged descriptor, which is the opposite of what evidence is for.
func (s Set) Documents() []Resolved {
	out := append([]Resolved{}, s.Project...)
	names := make([]string, 0, len(s.ByComponent))
	for name := range s.ByComponent {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, s.ByComponent[name]...)
	}
	return out
}
