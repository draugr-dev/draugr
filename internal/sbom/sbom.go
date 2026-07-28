// Package sbom generates Software Bills of Materials by shelling out to Syft.
//
// The document type and the Generator contract live in pkg/sbom; this package is the Syft
// implementation, kept internal so it can use internal/git and internal/toolexec.
package sbom

import (
	"context"
	"fmt"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	pkgsbom "github.com/draugr-dev/draugr/pkg/sbom"
)

// runner executes a command and returns its stdout. Injectable so tests don't need Syft.
type runner func(ctx context.Context, dir string, argv []string) ([]byte, error)

// checkouter clones a repository and returns its path plus a cleanup. Injectable for tests.
type checkouter func(ctx context.Context, url, revision string) (string, func(), error)

// Generator implements pkgsbom.Generator by shelling out to Syft. The zero value is not
// usable; use New.
var _ pkgsbom.Generator = (*Generator)(nil)

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
//		syft scan <src> -o <format> -q
//
//	  - "scan" is the explicit subcommand; Syft's bare-argument form is deprecated.
//	  - -q silences the progress UI so stdout is only the document.
//
// The source is a directory path (prefixed dir: so Syft can't misread a path as an image
// reference) or an image reference.
func argv(src string, format saga.SBOMFormat) []string {
	return []string{Binary, "scan", src, "-o", string(format), "-q"}
}

// Generate produces an SBOM for one target. Repositories are checked out first; images are
// handed to Syft by reference, which reads the registry directly and needs no local copy.
func (g *Generator) Generate(ctx context.Context, component string, t plugin.Target, format saga.SBOMFormat) (pkgsbom.Document, error) {
	if format == "" {
		format = pkgsbom.DefaultFormat
	}
	if !format.Valid() {
		return pkgsbom.Document{}, fmt.Errorf("unknown sbom format %q (want one of %v)", format, saga.SBOMFormats)
	}

	var src, label string
	switch target := t.(type) {
	case plugin.RepositoryTarget:
		dir, cleanup, err := g.checkout(ctx, target.URL, target.Revision)
		if err != nil {
			return pkgsbom.Document{}, fmt.Errorf("checkout %s: %w", target.URL, err)
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
		return pkgsbom.Document{}, fmt.Errorf("sbom: no inventory to take from a %s target", t.Kind())
	}

	out, err := g.run(ctx, "", argv(src, format))
	if err != nil {
		return pkgsbom.Document{}, fmt.Errorf("syft %s: %w", label, err)
	}
	if len(out) == 0 {
		return pkgsbom.Document{}, fmt.Errorf("syft %s: produced an empty document", label)
	}
	return pkgsbom.Document{Component: component, Target: label, Format: format, Bytes: out}, nil
}
