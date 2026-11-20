package report

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// ImageDeclarations is where each image model declares is written in the repository a run's code
// scanning upload belongs to, for Data.Declared.
//
// inRepository names a file on disk by its path in that repository, slash-separated, and says false
// for a file outside it. An image with no file or line, such as one a survey found or one a fragment
// from another repository declared, has no entry, and neither does one declared in a file
// inRepository refuses: a path in some other repository would put the finding on a file in this one
// that does not declare the image.
//
// Each image is keyed under its component by both spellings a finding names it by: the reference
// the scanners pulled, which carries the digest written beside it (`registry/app:1.2@sha256:…`), as
// the image findings' `image` property does, and `image:` as written, as a finding that has no such
// property carries it as its location.
func ImageDeclarations(model *saga.Model, inRepository func(file string) (string, bool)) sarif.Declarations {
	if model == nil || inRepository == nil {
		return nil
	}
	var out sarif.Declarations
	for _, comp := range model.Components {
		for _, img := range comp.Images {
			if img.File == "" || img.Line < 1 {
				continue
			}
			path, ok := inRepository(img.File)
			if !ok {
				continue
			}
			if out == nil {
				out = sarif.Declarations{}
			}
			at := sarif.Declaration{Path: path, Line: img.Line}
			// The target the images control plans, so the reference is the one its findings carry.
			pulled := plugin.ImageTarget{Ref: img.Image, Digest: img.Digest}.PinnedRef()
			for _, ref := range []string{pulled, img.Image} {
				key := sarif.DeclaredImage{Component: comp.Name, Ref: ref}
				if _, seen := out[key]; !seen {
					out[key] = at
				}
			}
		}
	}
	return out
}
