// Package sbom is the Software Bill of Materials surface: the document type a run produces and
// the contract for producing one.
//
// An SBOM is deliberately *not* a control. A control answers "did this check find anything?",
// and its verdict feeds the gate. An SBOM finds nothing — it is an inventory. Modelling it as a
// control would put a row in the results table that always reads "pass" without ever having
// looked, which is exactly the meaningless green Draugr exists to remove. So SBOMs travel as
// evidence: produced during a run, attached to the output, never consulted for the verdict.
//
// The generator that shells out to Syft lives in internal/sbom. This package holds only what
// callers need to name, so pkg/ keeps its rule of not importing internal/. Turning documents
// into deliverable artifacts lives in pkg/report, which owns the Artifact type — putting it
// here would make pkg/sbom import pkg/report, which imports pkg/engine, which imports this.
package sbom

import (
	"context"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// DefaultFormat is used when a Saga enables SBOM generation without naming a format.
const DefaultFormat = saga.SBOMCycloneDXJSON

// Document is one generated SBOM: the bytes, plus enough provenance to name the file and to
// know what it actually describes.
type Document struct {
	// Component is the Saga component the target belongs to.
	Component string
	// Target is the repository URL or image reference the SBOM was taken from.
	Target string
	// Format is the SBOM format the bytes are in.
	Format saga.SBOMFormat
	// Bytes is the SBOM document itself.
	Bytes []byte
}

// Generator produces an SBOM for one target. The engine takes this rather than a concrete
// implementation, the same way it takes registered scanners rather than importing them.
type Generator interface {
	Generate(ctx context.Context, component string, t plugin.Target, format saga.SBOMFormat) (Document, error)
}
