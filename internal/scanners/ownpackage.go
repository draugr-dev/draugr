package scanners

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// markOwnPackages marks each finding whose package is the project itself in the file it was found
// in: the root or a workspace member of a package-lock.json, a Cargo.lock entry with no source, a
// pubspec.yaml that says publish_to: none, a pod a Podfile.lock takes from a :path:.
//
// A scanner reads such a package as it reads a dependency and matches it against the advisories of
// whatever published package shares its name. Grype reports a lockfile's root and a workspace member
// that way, and gives a workspace member no package URL, so its copy is never correlated with
// Trivy's. The file in the checkout says which package is the project's own, so the mark is read
// here, where it reaches every scanner's finding about that package in that file.
//
// Every repository scanner's findings pass through, after their paths are repository-relative and
// while the checkout still exists, as markPomScopes's do. A file that cannot be read or parsed marks
// nothing.
func markOwnPackages(results []sarif.Result, dir string) {
	files := map[string][]manifests.OwnPackage{}
	for i := range results {
		res := &results[i]
		if res.Package == nil || res.Package.Own || !manifests.OwnFile(res.Location.URI) {
			continue
		}
		own, read := files[res.Location.URI]
		if !read {
			own = manifests.OwnPackages(res.Location.URI, checkoutReader(dir))
			files[res.Location.URI] = own
		}
		for _, o := range own {
			if o.Matches(res.Package.Name, res.Package.Version) {
				// A copy, because a scanner may hand several findings the same package value.
				pkg := *res.Package
				pkg.Own = true
				res.Package = &pkg
				break
			}
		}
	}
}

// errOutsideCheckout is what checkoutReader returns for a path that leaves the checkout.
var errOutsideCheckout = errors.New("path leaves the checkout")

// checkoutReader reads a repository-relative, slash-separated path inside the checkout at dir, and
// refuses one that leaves it.
func checkoutReader(dir string) func(rel string) ([]byte, error) {
	return func(rel string) ([]byte, error) {
		local := filepath.FromSlash(rel)
		if !filepath.IsLocal(local) {
			return nil, errOutsideCheckout
		}
		return os.ReadFile(filepath.Join(dir, local)) // #nosec G304 -- a local path inside the checkout
	}
}
