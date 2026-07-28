// Package sbom generates Software Bills of Materials for the things a Saga describes.
//
// An SBOM is deliberately *not* a control. A control answers "did this check find anything?",
// and its verdict feeds the gate. An SBOM finds nothing — it is an inventory. Modelling it as a
// control would put a row in the results table that always reads "pass" without ever having
// looked, which is exactly the meaningless green Draugr exists to remove. So SBOMs travel as
// evidence: produced during a run, attached to the output, and never consulted for the verdict.
package sbom

import (
	"context"
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
)

// The SBOM formats Draugr can emit. Both are open specifications that downstream tooling
// (vulnerability scanners, VEX processors, procurement review) already reads.
const (
	// FormatSPDXJSON is the default. It matches what Draugr's own releases publish, and it is
	// the ISO standard (ISO/IEC 5962).
	FormatSPDXJSON = "spdx-json"
	// FormatCycloneDXJSON is the OWASP format, common in security tooling.
	FormatCycloneDXJSON = "cyclonedx-json"
)

// Formats lists the supported SBOM formats, for validation messages and docs.
func Formats() []string { return []string{FormatSPDXJSON, FormatCycloneDXJSON} }

// ValidFormat reports whether f is a format Draugr can emit. The empty string is valid and
// means "the default".
func ValidFormat(f string) bool {
	return f == "" || f == FormatSPDXJSON || f == FormatCycloneDXJSON
}

// Document is one generated SBOM: the bytes, plus enough provenance to name the file and to
// know what it actually describes.
type Document struct {
	// Component is the Saga component the target belongs to.
	Component string
	// Target is the repository URL or image reference the SBOM was taken from.
	Target string
	// Format is the SBOM format the bytes are in (see FormatSPDXJSON, FormatCycloneDXJSON).
	Format string
	// Bytes is the SBOM document itself.
	Bytes []byte
}

// runner executes a command and returns its stdout. Injectable so tests don't need Syft.
type runner func(ctx context.Context, dir string, argv []string) ([]byte, error)

// checkouter clones a repository and returns its path plus a cleanup. Injectable for tests.
type checkouter func(ctx context.Context, url, revision string) (string, func(), error)

// Generator produces SBOMs. The zero value is not usable; use New.
type Generator struct {
	run      runner
	checkout checkouter
}

// New returns a Generator that shells out to Syft and clones with git.
func New() *Generator {
	return &Generator{run: toolexec.Run, checkout: git.Checkout}
}

// Binary is the tool Generate requires on PATH.
const Binary = "syft"

// argv builds Syft's command line for a source it can already reach:
//
//	syft scan <src> -o <format> -q
//
//   - "scan" is the explicit subcommand; Syft's bare-argument form is deprecated.
//   - -q silences the progress UI so stdout is only the document.
//
// The source is a directory path (prefixed dir: so Syft can't misread a path as an image
// reference) or an image reference.
func argv(src, format string) []string {
	return []string{Binary, "scan", src, "-o", format, "-q"}
}

// Generate produces an SBOM for one target. Repositories are checked out first; images are
// handed to Syft by reference, which reads the registry directly and needs no local copy.
func (g *Generator) Generate(ctx context.Context, component string, t plugin.Target, format string) (Document, error) {
	if format == "" {
		format = FormatSPDXJSON
	}
	if !ValidFormat(format) {
		return Document{}, fmt.Errorf("unknown sbom format %q (want %s)", format, strings.Join(Formats(), " or "))
	}

	var src, label string
	switch target := t.(type) {
	case plugin.RepositoryTarget:
		dir, cleanup, err := g.checkout(ctx, target.URL, target.Revision)
		if err != nil {
			return Document{}, fmt.Errorf("checkout %s: %w", target.URL, err)
		}
		defer cleanup()
		// dir: disambiguates a local path from an image reference — Syft guesses otherwise,
		// and a directory named like a registry path is not a hypothetical we want to debug.
		src, label = "dir:"+dir, target.URL
	case plugin.ImageTarget:
		src = target.PinnedRef()
		label = src
	default:
		// Hosts and infrastructure have no package inventory to take. Returning an error rather
		// than an empty document keeps "we produced nothing" from looking like a valid SBOM.
		return Document{}, fmt.Errorf("sbom: no inventory to take from a %s target", t.Kind())
	}

	out, err := g.run(ctx, "", argv(src, format))
	if err != nil {
		return Document{}, fmt.Errorf("syft %s: %w", label, err)
	}
	if len(out) == 0 {
		return Document{}, fmt.Errorf("syft %s: produced an empty document", label)
	}
	return Document{Component: component, Target: label, Format: format, Bytes: out}, nil
}

// extensions maps a format to the file suffix its consumers expect.
var extensions = map[string]string{
	FormatSPDXJSON:      "spdx.json",
	FormatCycloneDXJSON: "cdx.json",
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
