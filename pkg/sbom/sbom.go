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
// callers need to name, so pkg/ keeps its rule of not importing internal/.
package sbom

import (
	"context"
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// DefaultFormat is used when a Saga enables SBOM generation without naming a format.
const DefaultFormat = saga.SBOMSPDXJSON

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

// extensions maps a format to the file suffix its consumers expect.
var extensions = map[saga.SBOMFormat]string{
	saga.SBOMSPDXJSON:      "spdx.json",
	saga.SBOMCycloneDXJSON: "cdx.json",
}

// Artifacts converts documents into the unit publishers deliver (pkg/report.Artifact), so SBOMs
// travel the same path as every other output rather than needing their own delivery mechanism.
func Artifacts(docs []Document) []report.Artifact {
	arts := make([]report.Artifact, 0, len(docs))
	for _, d := range docs {
		ext := extensions[d.Format]
		if ext == "" {
			ext = "json"
		}
		arts = append(arts, report.Artifact{
			Format:      "sbom",
			Filename:    fmt.Sprintf("sbom-%s-%s.%s", slug(d.Component), slug(d.Target), ext),
			ContentType: "application/json",
			Bytes:       d.Bytes,
		})
	}
	return arts
}

// slug makes a filesystem-safe fragment out of a component name or a target reference. Registry
// paths, tags and digests all carry characters that are awkward or illegal in filenames, and two
// images in one component must not collapse onto the same name — so every unsafe run becomes a
// single dash rather than being dropped.
func slug(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
