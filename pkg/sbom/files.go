package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// fileTypes maps a format to the file suffix and media type its consumers expect. Not every SBOM
// is JSON, and labeling an XML or tag-value document application/json would be wrong the moment a
// publisher does anything with the media type.
var fileTypes = map[saga.SBOMFormat]struct{ ext, mediaType string }{
	saga.SBOMCycloneDXJSON: {"cdx.json", "application/vnd.cyclonedx+json"},
	saga.SBOMCycloneDXXML:  {"cdx.xml", "application/vnd.cyclonedx+xml"},
	saga.SBOMSPDXJSON:      {"spdx.json", "application/spdx+json"},
	saga.SBOMSPDXTagValue:  {"spdx", "text/spdx; charset=utf-8"},
}

// unmappedType is the suffix and media type of a format fileTypes does not name. Unreachable
// through the Saga, which validates the format at load time; a document is still written rather
// than dropped, because losing evidence would be worse than an imprecise suffix.
var unmappedType = struct{ ext, mediaType string }{"sbom", "application/octet-stream"}

func fileType(f saga.SBOMFormat) struct{ ext, mediaType string } {
	if t, ok := fileTypes[f]; ok {
		return t
	}
	return unmappedType
}

// MediaType is the media type a document in format f is delivered as.
func MediaType(f saga.SBOMFormat) string { return fileType(f).mediaType }

// Filenames names each document as `-o` writes it and every publisher delivers it, in the order
// given.
//
// Held here rather than beside the artifact type in pkg/report, because the run's own record names
// the same files and is rendered by a package pkg/report imports. Two derivations of one name are
// two answers to "which file is this", and the record is the one nobody would notice drifting.
func Filenames(docs []Document) []string {
	names := make([]string, 0, len(docs))
	taken := map[string]int{}
	for _, d := range docs {
		ext := fileType(d.Format).ext
		name := fmt.Sprintf("sbom-%s-%s.%s", slug(d.Component), slug(d.Target), ext)
		if d.Project {
			// The assembled document has no component or target to name it after, and "the
			// project" is the distinction a reader needs when both kinds are in one directory.
			name = "sbom-project." + ext
		}
		// One component can hold one repository twice, scoped to two paths: two inventories with
		// the same component and source. A numbered second name keeps the second from overwriting
		// the first when both are written to one directory.
		if n := taken[name]; n > 0 {
			taken[name]++
			name = strings.TrimSuffix(name, "."+ext) + fmt.Sprintf("-%d.", n+1) + ext
		} else {
			taken[name] = 1
		}
		names = append(names, name)
	}
	return names
}

// Digest is the SHA-256 of the document's bytes, the bytes written to its file, in the
// `sha256:<hex>` form the report uses for every digest.
func (d Document) Digest() string {
	sum := sha256.Sum256(d.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TargetName is what an inventory of t names it after: a repository by its source, which carries
// no credential, and an image by its pinned reference.
//
// The generator names each document with it, and a run names a target whose inventory failed with
// it, so a document and a failure for the same target read alike. Any other kind has no inventory
// to take and is named by its identity.
func TargetName(t plugin.Target) string {
	switch t := t.(type) {
	case plugin.RepositoryTarget:
		return t.Source()
	case plugin.ImageTarget:
		return t.PinnedRef()
	}
	return t.Identity()
}

// slug makes a filesystem-safe fragment out of a component name or a target reference. Registry
// paths, tags and digests all carry characters that are awkward or illegal in filenames, and two
// images in one component must not collapse onto the same name. So every unsafe run becomes a
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
