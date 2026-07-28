package report

import (
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// extensions maps a format to the file suffix its consumers expect.
var extensions = map[saga.SBOMFormat]string{
	saga.SBOMSPDXJSON:      "spdx.json",
	saga.SBOMCycloneDXJSON: "cdx.json",
}

// SBOMArtifacts converts SBOM documents into the unit publishers deliver, so SBOMs travel the
// same path as every other output rather than needing their own delivery mechanism.
func SBOMArtifacts(docs []sbom.Document) []Artifact {
	arts := make([]Artifact, 0, len(docs))
	for _, d := range docs {
		ext := extensions[d.Format]
		if ext == "" {
			ext = "json"
		}
		arts = append(arts, Artifact{
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
