package sbom

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// cycloneDX is as much of the specification as assembling a project document needs.
//
// Hand-modelled, and deliberately partial. Draugr does not adopt a package model — every field
// below exists to move a component or an edge from one document into another, and a field nobody
// reads is one more thing to keep in step with a spec that keeps moving. The parts of a source
// document this does not name survive as far as they are carried; the parts it does are the ones
// the assembled hierarchy is built from.
type cycloneDX struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Component *cdxComponent `json:"component,omitempty"`
	Tools     *cdxTools     `json:"tools,omitempty"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components,omitempty"`
}

type cdxComponent struct {
	Type       string          `json:"type"`
	BOMRef     string          `json:"bom-ref,omitempty"`
	Name       string          `json:"name"`
	Version    string          `json:"version,omitempty"`
	PURL       string          `json:"purl,omitempty"`
	CPE        string          `json:"cpe,omitempty"`
	Licenses   []cdxLicense    `json:"licenses,omitempty"`
	Hashes     []cdxHash       `json:"hashes,omitempty"`
	Properties []cdxProperty   `json:"properties,omitempty"`
	Supplier   *cdxOrganizaton `json:"supplier,omitempty"`
}

type cdxLicense struct {
	License *cdxLicenseChoice `json:"license,omitempty"`
	Expr    string            `json:"expression,omitempty"`
}

type cdxLicenseChoice struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxOrganizaton struct {
	Name string `json:"name,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// assembledSpecVersion is the CycloneDX version the assembled document claims.
//
// Fixed rather than inherited from whichever input happened to be read first. A document built
// from several sources has to state one version, and stating the one this code was written
// against is the only claim that is true regardless of what syft emits next.
const assembledSpecVersion = "1.6"

// ref is a package's identity within the assembled document.
//
// A purl is the right answer where there is one: it is what a consumer matches against, and it is
// what makes the same package arriving from two targets collapse to a single entry. The fallback
// is a digest rather than the name, because two different versions of one library must not
// resolve to the same node — that would silently merge them, and the graph would then claim a
// dependency that does not exist.
func (c cdxComponent) ref() string {
	if c.PURL != "" {
		return c.PURL
	}
	sum := sha256.Sum256([]byte(c.Type + "\x00" + c.Name + "\x00" + c.Version + "\x00" + c.CPE))
	return "draugr:pkg/" + hex.EncodeToString(sum[:12])
}

// newCycloneDX starts an assembled document whose root component is the release — because the
// release is the product, and the product is what an SBOM is asked for.
func newCycloneDX(release saga.Release) cycloneDX {
	return cycloneDX{
		BOMFormat:   "CycloneDX",
		SpecVersion: assembledSpecVersion,
		Version:     1,
		Metadata: cdxMetadata{
			Component: &cdxComponent{
				Type:    "application",
				BOMRef:  "draugr:release/" + release.Name,
				Name:    release.Name,
				Version: release.Version,
			},
		},
	}
}
