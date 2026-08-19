package vex

import (
	"sort"
	"strings"
)

// Claim is one supplier statement, resolved to the form a run can act on.
//
// Flattened out of the document's product/subcomponent nesting because that nesting describes how
// the supplier thinks about their artifact, and a scan finds packages. One statement naming three
// subcomponents is three claims here, which is what makes matching a lookup rather than a search.
type Claim struct {
	// Vulnerability is the identifier the statement is about, e.g. "CVE-2024-1234".
	Vulnerability string
	// PURL is the package the claim applies to — the subcomponent when the statement named one,
	// otherwise the product itself. Empty when the statement identified neither by package URL,
	// in which case the claim applies to every finding for that vulnerability in the component
	// that declared the source. See Index.
	PURL string
	// Status is the claim: not_affected, affected, fixed, under_investigation.
	Status string
	// Justification is VEX's vocabulary term, present only with not_affected.
	Justification string
	// Statement is the prose the supplier gave — impact_statement for not_affected, otherwise
	// action_statement or status_notes. What a reader needs when deciding whether to believe it.
	Statement string
	// Author is who asserted it, carried from the document so a claim never travels anonymously.
	Author string
	// Source is the document this came from, for the same reason.
	Source string
	// Timestamp is when the claim was made, statement-level where the statement carried one and
	// the document's otherwise.
	Timestamp string
}

// statusRank orders statuses by how much exposure they concede, least first.
//
// The same ordering the producer uses, and for the same reason: when two statements disagree
// about one vulnerability, the one conceding *more* exposure wins. Believing the safer of two
// contradictory supplier claims is how a tool talks somebody into shipping something.
var statusRank = map[string]int{
	"fixed":               0,
	"not_affected":        1,
	"under_investigation": 2,
	"affected":            3,
}

// Claims flattens a document into the claims it makes.
func (d Document) Claims(source string) []Claim {
	var out []Claim
	for _, st := range d.Statements {
		when := st.Timestamp
		if when == "" {
			when = d.Timestamp
		}
		base := Claim{
			Vulnerability: st.Vulnerability.Name,
			Status:        st.Status,
			Justification: st.Justification,
			Statement:     prose(st),
			Author:        d.Author,
			Source:        source,
			Timestamp:     when,
		}
		if base.Vulnerability == "" {
			continue // a statement about nothing identifiable cannot be matched to a finding
		}
		for _, p := range st.Products {
			if len(p.Subcomponents) == 0 {
				c := base
				c.PURL = normalizePURL(p.ID)
				out = append(out, c)
				continue
			}
			for _, sub := range p.Subcomponents {
				c := base
				c.PURL = normalizePURL(sub.ID)
				out = append(out, c)
			}
		}
		// A statement with no products at all still says something about the vulnerability. Kept
		// with an empty PURL, which Index treats as applying to any package — narrowed by the
		// component that declared the source, which is the whole reason that scoping exists.
		if len(st.Products) == 0 {
			out = append(out, base)
		}
	}
	return out
}

// prose picks the human-readable half of a statement.
func prose(st Statement) string {
	switch {
	case st.ImpactStatement != "":
		return st.ImpactStatement
	case st.ActionStatement != "":
		return st.ActionStatement
	}
	return st.StatusNotes
}

// normalizePURL reduces a package URL to the part two tools will agree on.
//
// Qualifiers and subpaths are dropped: `pkg:deb/debian/openssl@3.0.11?arch=amd64` and the same
// purl without the arch are the same package to a supplier making a claim about it, and keeping
// them distinct means a correct statement silently matches nothing. Case is normalized for the
// scheme and type only, which the purl spec says are case-insensitive — the name and version are
// not, and lowercasing them would make `pkg:golang/github.com/Masterminds/semver` a different
// package from itself.
//
// Not a full purl parser: this compares identifiers rather than interpreting them, and a
// dependency that can only ever produce a subset of what it parses is a dependency that can be
// wrong in ways this file cannot see.
func normalizePURL(id string) string {
	s := strings.TrimSpace(id)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	// Only `pkg:` identifiers are package URLs. Anything else — an OCI reference, a vendor's own
	// product IRI — is returned as written, because guessing at its shape is how a match happens
	// for the wrong reason.
	if !strings.HasPrefix(strings.ToLower(s), "pkg:") {
		return s
	}
	rest := s[len("pkg:"):]
	if i := strings.Index(rest, "/"); i > 0 {
		return "pkg:" + strings.ToLower(rest[:i]) + rest[i:]
	}
	return "pkg:" + rest
}

// Index is the claims from one or more documents, ready to be asked about a finding.
//
// Built per component. A supplier's claim about their artifact must not reach another component's
// findings — that is the failure that turns one vendor's assurance into a silent suppression
// somewhere nobody was looking.
type Index struct {
	// byVulnPURL is keyed on vulnerability + normalized purl; byVuln holds the claims that named
	// no package and so apply to any finding for that vulnerability in this component.
	byVulnPURL map[string]Claim
	byVuln     map[string]Claim
	// count is how many claims went in, before conflicts were resolved.
	count int
}

// NewIndex builds a lookup from claims, resolving conflicts by conceded exposure.
func NewIndex(claims []Claim) *Index {
	ix := &Index{byVulnPURL: map[string]Claim{}, byVuln: map[string]Claim{}, count: len(claims)}
	for _, c := range claims {
		if c.PURL == "" {
			keepStronger(ix.byVuln, c.Vulnerability, c)
			continue
		}
		keepStronger(ix.byVulnPURL, c.Vulnerability+"\x00"+c.PURL, c)
	}
	return ix
}

// keepStronger stores c unless what is already there concedes more exposure.
func keepStronger(m map[string]Claim, key string, c Claim) {
	if prev, seen := m[key]; seen && statusRank[prev.Status] >= statusRank[c.Status] {
		return
	}
	m[key] = c
}

// Count is how many claims this index was built from.
func (ix *Index) Count() int { return ix.count }

// Lookup finds the claim covering a finding, if there is one.
//
// A claim naming the package beats one that named no package: the specific statement is the one
// the supplier thought about.
//
// The key it matched on comes back with it, and has to, because the two maps are keyed
// differently. A caller that reconstructed the key from the finding would record the wrong one
// every time a lookup fell through to a package-less claim, and Unmatched would then report a
// claim that had in fact been applied — a supplier told their correct statement was ignored.
func (ix *Index) Lookup(vulnerability, purl string) (claim Claim, key string, ok bool) {
	if ix == nil || vulnerability == "" {
		return Claim{}, "", false
	}
	if purl != "" {
		k := vulnerability + "\x00" + normalizePURL(purl)
		if c, found := ix.byVulnPURL[k]; found {
			return c, k, true
		}
	}
	c, found := ix.byVuln[vulnerability]
	return c, vulnerability, found
}

// Unmatched names the claims nothing in the run matched, sorted.
//
// A supplier document that matches nothing is doing nothing, and looks exactly like one that is
// working — the same argument the descriptor's own exclusions are held to. Usually it means the
// supplier and the scanner disagree about how a package is named, which is a real finding about
// the document rather than a quiet no-op.
func (ix *Index) Unmatched(used map[string]bool) []Claim {
	if ix == nil {
		return nil
	}
	var out []Claim
	for key, c := range ix.byVulnPURL {
		if !used[key] {
			out = append(out, c)
		}
	}
	for vuln, c := range ix.byVuln {
		if !used[vuln] {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vulnerability != out[j].Vulnerability {
			return out[i].Vulnerability < out[j].Vulnerability
		}
		return out[i].PURL < out[j].PURL
	})
	return out
}
