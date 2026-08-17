// Package sbom is the Software Bill of Materials surface: the document type a run produces and
// the contract for producing one.
//
// An SBOM is deliberately *not* a control. A control answers "did this check find anything?",
// and its verdict feeds the gate. An SBOM finds nothing — it is an inventory. Modeling it as a
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
	// Component is the Saga component the target belongs to. Empty on a project document, which
	// covers all of them.
	Component string
	// Target is the repository URL or image reference the SBOM was taken from. Empty on a
	// project document, which was assembled rather than taken from anything.
	Target string
	// Project marks the assembled document covering the whole release. A run may carry one
	// alongside the per-target documents it was built from.
	Project bool
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

// Assembler combines per-target documents into one covering the whole release.
//
// Optional, and discovered by type assertion on the Generator — the same shape as the scanner
// SDK's CacheVersioner and Prewarmer. A generator that cannot assemble is not broken; it just
// cannot serve `scope: project`, and the engine says so rather than quietly emitting the parts.
//
// Assembling is not merging. A generic merge tool has a pile of documents and has to guess how
// they relate; this one is handed the release and the components, which is the hierarchy the
// assembled document needs and the reason its output can be more than a concatenation.
type Assembler interface {
	Assemble(release saga.Release, format saga.SBOMFormat, docs []Document) (Document, error)
}
