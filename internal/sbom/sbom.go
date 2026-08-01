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
type checkouter func(ctx context.Context, url, revision string, scope git.Scope) (string, func(), error)

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

// argv builds Syft's command line:
//
//		syft scan <src> -o <format> -q [--source-name <name>]
//
//	  - "scan" is the explicit subcommand; Syft's bare-argument form is deprecated.
//	  - -q silences the progress UI so stdout is only the document.
//	  - --source-name overrides what the document calls the thing it describes.
//
// The source is a directory path (prefixed dir: so Syft can't misread a path as an image
// reference) or an image reference.
//
// name matters more than it looks for repositories. Left alone, Syft names the document after
// the path it scanned — which for us is a temporary clone, so the document would read
// "/tmp/draugr-repo-1956481920": meaningless to a consumer, and different on every run, so two
// SBOMs of the same commit would never compare equal. Images already carry a stable reference
// and are left as Syft found them.
func argv(src string, format saga.SBOMFormat, name string) []string {
	a := []string{Binary, "scan", src, "-o", string(format), "-q"}
	if name != "" {
		a = append(a, "--source-name", name)
	}
	return a
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

	var src, label, sourceName string
	switch target := t.(type) {
	case plugin.RepositoryTarget:
		dir, cleanup, err := g.checkout(ctx, target.URL, target.Revision,
			git.Scope{Paths: target.Paths, Ignore: target.Ignore})
		if err != nil {
			return pkgsbom.Document{}, fmt.Errorf("checkout %s: %w", target.URL, err)
		}
		defer cleanup()
		// dir: disambiguates a local path from an image reference — Syft guesses otherwise,
		// and a directory named like a registry path is not a hypothetical we want to debug.
		src, label, sourceName = "dir:"+dir, target.URL, target.URL
	case plugin.ImageTarget:
		src = target.PinnedRef()
		label = src
	default:
		// Hosts and infrastructure have no package inventory to take. Returning an error rather
		// than an empty document keeps "we produced nothing" from looking like a valid SBOM.
		return pkgsbom.Document{}, fmt.Errorf("sbom: no inventory to take from a %s target", t.Kind())
	}

	out, err := g.run(ctx, "", argv(src, format, sourceName))
	if err != nil {
		return pkgsbom.Document{}, fmt.Errorf("syft %s: %w", label, err)
	}
	if len(out) == 0 {
		return pkgsbom.Document{}, fmt.Errorf("syft %s: produced an empty document", label)
	}
	return pkgsbom.Document{Component: component, Target: label, Format: format, Bytes: out}, nil
}
