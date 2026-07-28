package report

import (
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// sbomMeta maps a format to the file suffix and media type its consumers expect, mirroring
// formatMeta for reports. Not every SBOM is JSON — labelling an XML or tag-value document
// application/json would be wrong the moment a publisher does anything with the media type.
var sbomMeta = map[saga.SBOMFormat]struct{ ext, contentType string }{
	saga.SBOMSPDXJSON:      {"spdx.json", "application/spdx+json"},
	saga.SBOMSPDXTagValue:  {"spdx", "text/spdx; charset=utf-8"},
	saga.SBOMCycloneDXJSON: {"cdx.json", "application/vnd.cyclonedx+json"},
	saga.SBOMCycloneDXXML:  {"cdx.xml", "application/vnd.cyclonedx+xml"},
}

// SBOMArtifacts converts SBOM documents into the unit publishers deliver, so SBOMs travel the
// same path as every other output rather than needing their own delivery mechanism.
func SBOMArtifacts(docs []sbom.Document) []Artifact {
	arts := make([]Artifact, 0, len(docs))
	for _, d := range docs {
		meta, ok := sbomMeta[d.Format]
		if !ok {
			// Unreachable via the Saga, which validates the format at load time. A document
			// still gets written rather than dropped: losing evidence would be worse than an
			// imprecise suffix.
			meta = struct{ ext, contentType string }{"sbom", "application/octet-stream"}
		}
		arts = append(arts, Artifact{
			Format:      "sbom",
			Filename:    fmt.Sprintf("sbom-%s-%s.%s", slug(d.Component), slug(d.Target), meta.ext),
			ContentType: meta.contentType,
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
