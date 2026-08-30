package saga

import "slices"

// VEXConfig names the party making the claims in a generated VEX document, and the product they
// are about.
//
// Both are optional and both are worth setting for a document you publish. A VEX document is an
// assertion by a supplier about their own product, so the two things a consumer needs are *who
// says so* and *what about*. Draugr can guess the second from the release and cannot guess the
// first at all — it knows a project name, not a legal entity or a contact.
type VEXConfig struct {
	// Author identifies who is making these statements: an organization, ideally with a way to
	// reach them ("Example Ltd <security@example.com>"). Defaults to the release name, which is
	// a project rather than a party — enough to produce a valid document, not enough for one
	// you would hand to a customer.
	Author string `yaml:"author,omitempty"`
	// Product identifies the thing the statements are about, as an IRI — a package URL is the
	// conventional choice ("pkg:oci/example/api@sha256:…").
	//
	// Defaults to the top-level `publishes`, and to a purl built from the project name and
	// version where that is unset too. Set it only where a VEX document has to name this product
	// differently from everything else that identifies it, which is rare: an identifier is an
	// identifier, and two of them are two things to keep in step.
	//
	// A VEX statement is matched to a component by identifier, so a document naming the product
	// differently from a consumer's own bill of materials is one nothing will apply.
	Product string `yaml:"product,omitempty"`
}

// VEXDecision states what a suppression means in VEX terms. Optional, and absent is a perfectly
// good answer — see the status table below for what Draugr emits without it.
//
// This is separate from `reason` because they answer different questions. A reason is written for
// a human reviewing the descriptor; a VEX status is a machine-readable claim about the product,
// which downstream consumers act on. Deriving one from the other would mean inferring a
// compliance statement from free text, and detection, severity and evidence in Draugr do not
// involve inference.
type VEXDecision struct {
	// Status is the claim: not_affected, affected, or fixed.
	//
	// under_investigation is deliberately not accepted here. It is what an untriaged finding
	// already reports, and claiming it on a finding you have suppressed says two contradictory
	// things — that the matter is open, and that it is settled.
	Status string `yaml:"status"`
	// Justification is why the product is not affected, from VEX's fixed vocabulary. Valid only
	// with not_affected, where VEX requires either this or a prose statement; without it the
	// exclusion's `reason` is emitted as the prose form instead.
	//
	// A closed vocabulary because the whole value of the field is that a consumer can act on it
	// without reading English.
	Justification string `yaml:"justification,omitempty"`
}

// The VEX statuses a suppression may declare.
const (
	// VEXNotAffected claims the vulnerability is present but cannot affect this product.
	VEXNotAffected = "not_affected"
	// VEXAffected admits the product is affected and something should be done about it.
	VEXAffected = "affected"
	// VEXFixed claims a remediation has already been applied.
	VEXFixed = "fixed"
	// VEXUnderInvestigation says the question is open. Draugr emits this for findings nobody has
	// triaged; it is not a value an exclusion may declare.
	VEXUnderInvestigation = "under_investigation"
)

// VEXStatuses are the statuses an exclusion may declare.
var VEXStatuses = []string{VEXNotAffected, VEXAffected, VEXFixed}

// VEXJustifications is VEX's fixed vocabulary for why a product is not affected.
var VEXJustifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// ValidVEXStatus reports whether s is a status an exclusion may declare.
func ValidVEXStatus(s string) bool { return slices.Contains(VEXStatuses, s) }

// ValidVEXJustification reports whether j is one of VEX's not_affected justifications.
func ValidVEXJustification(j string) bool { return slices.Contains(VEXJustifications, j) }
