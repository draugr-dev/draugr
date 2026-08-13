package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// gitlabSBOMSpecVersion is the CycloneDX version this document declares.
//
// GitLab reads 1.4, 1.5 and 1.6 and rejects anything else outright — a 1.7 document is not
// partially understood, it is "could not be parsed", and the surfaces built on it stay empty while
// the scan that produced it reports success.
const gitlabSBOMSpecVersion = "1.6"

// gitlabSBOMReporter renders the SBOM in the dialect GitLab reads.
//
// A separate document rather than a change to the SBOM Draugr already writes. That one is correct
// CycloneDX which other consumers read; pinning its spec version to whatever GitLab currently
// supports, and filling its components with one vendor's property namespace, would make every other
// consumer pay for this one. So the canonical SBOM stays as it is and this is rendered beside it.
//
// Two facts GitLab needs are already present under different names — the manifest a package came
// from, which Syft records as `syft:location:N:path`, and the package manager, which is the type in
// every component's purl. Neither is inferred; both are translated.
type gitlabSBOMReporter struct{}

func (gitlabSBOMReporter) Format() string { return "gitlab-cyclonedx" }

func (gitlabSBOMReporter) Render(w io.Writer, d Data) error {
	doc, err := gitlabSBOMSource(d.Run.SBOMs)
	if err != nil {
		return err
	}
	doc["specVersion"] = gitlabSBOMSpecVersion

	comps, _ := doc["components"].([]any)
	kept := make([]any, 0, len(comps))
	for _, raw := range comps {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		purl, _ := c["purl"].(string)
		// Only packages. An SBOM also describes the tree it was taken from — the component, the
		// checkout, the manifest itself — and those carry no purl, no version and nothing GitLab's
		// dependency list can show. Passing them on produces rows that name a file as a dependency.
		if purl == "" {
			continue
		}
		gitlabStampComponent(c, purl)
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		return fmt.Errorf("gitlab-cyclonedx: the SBOM contains no packages, so there is nothing " +
			"for GitLab's dependency list to show")
	}
	doc["components"] = kept

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// gitlabSBOMSource picks the document to translate, preferring the assembled one.
//
// The project document covers every component in one file, which is what GitLab's dependency list
// is a view of. Per-target documents are the fallback for a run scoped to one of them.
func gitlabSBOMSource(docs []sbom.Document) (map[string]any, error) {
	var chosen *sbom.Document
	for i, doc := range docs {
		if doc.Format != saga.SBOMCycloneDXJSON {
			continue
		}
		if doc.Project {
			chosen = &docs[i]
			break
		}
		if chosen == nil {
			chosen = &docs[i]
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("gitlab-cyclonedx needs a CycloneDX JSON SBOM and this run produced " +
			"none — enable `config.sbom` with `format: cyclonedx-json`")
	}
	var out map[string]any
	if err := json.Unmarshal(chosen.Bytes, &out); err != nil {
		return nil, fmt.Errorf("gitlab-cyclonedx: reading the SBOM: %w", err)
	}
	return out, nil
}

// gitlabStampComponent adds the two properties GitLab reads, keeping everything already there.
//
// Decoded into a map rather than a typed model on purpose: an SBOM carries fields Draugr has no
// opinion about, and round-tripping through a struct would quietly drop whatever it did not know.
func gitlabStampComponent(c map[string]any, purl string) {
	props, _ := c["properties"].([]any)
	add := func(name, value string) {
		if value == "" {
			return
		}
		props = append(props, map[string]any{"name": name, "value": value})
	}
	add("gitlab:dependency_scanning:package_manager:name", gitlabPackageManager(purl))
	add("gitlab:dependency_scanning:input_file:path", gitlabInputFile(props))
	c["properties"] = props
}

// gitlabInputFile is the manifest a package was found in, repository-relative.
//
// Syft records absolute paths within the scanned tree ("/requirements.txt"); GitLab wants them
// relative to the repository root, and reads the first one — a package found in several manifests
// is still declared by one of them.
func gitlabInputFile(props []any) string {
	for _, raw := range props {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		if !strings.HasPrefix(name, "syft:location:") || !strings.HasSuffix(name, ":path") {
			continue
		}
		if v, _ := p["value"].(string); v != "" {
			return strings.TrimPrefix(v, "/")
		}
	}
	return ""
}

// gitlabPackageManagers maps a purl type to the package manager GitLab names.
//
// Only where the two vocabularies genuinely differ. An unmapped type is passed through rather than
// dropped: purl types are already ecosystem names, so "cargo" is a true answer to "which package
// manager", and a blank column is worse than one naming the ecosystem.
var gitlabPackageManagers = map[string]string{
	"pypi":   "pip",
	"gem":    "bundler",
	"golang": "go",
}

// gitlabPackageManager reads the ecosystem out of a purl: pkg:pypi/flask@0.12.2 -> pip.
func gitlabPackageManager(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	typ, _, _ := strings.Cut(rest, "/")
	if typ == "" {
		return ""
	}
	if mapped, ok := gitlabPackageManagers[typ]; ok {
		return mapped
	}
	return typ
}
