package report

import (
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// SBOMArtifacts converts SBOM documents into the unit publishers deliver, so SBOMs travel the
// same path as every other output rather than needing their own delivery mechanism.
//
// Named by sbom.Filenames, the function report.json's `sboms` block names them by, so the file a
// publisher delivers is the file the record describes.
func SBOMArtifacts(docs []sbom.Document) []Artifact {
	names := sbom.Filenames(docs)
	arts := make([]Artifact, 0, len(docs))
	for i, d := range docs {
		arts = append(arts, Artifact{
			Format:      "sbom",
			Filename:    names[i],
			ContentType: sbom.MediaType(d.Format),
			Bytes:       d.Bytes,
		})
	}
	return arts
}
