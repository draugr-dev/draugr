package scanners

import (
	"os"
	"path"
	"path/filepath"

	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/internal/versionorder"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// markPomScopes marks each finding about a dependency a pom.xml declares in a scope that does not
// ship with the application: provided or system as Provided, test as Dev.
//
// The scope is in the pom and not in what the scanners report. Trivy's pom parser leaves out every
// dependency outside compile and runtime scope, so it has no finding to mark, and Grype reports
// those dependencies with no scope at all, so its findings on them counted at full priority. Read
// here, from the file in the checkout, the mark reaches a finding whichever scanner reported it.
//
// Every repository scanner's findings pass through, after their paths are repository-relative and
// while the checkout still exists. A finding is read only where its package is a Maven package and
// its location is a pom.xml; a dependency the pom does not declare, a pom that does not parse, and
// a scope this pom leaves to a parent POM all leave the finding unmarked, which counts it as
// runtime (see manifests.PomScopes).
func markPomScopes(results []sarif.Result, dir string) {
	poms := map[string]map[string]manifests.Scope{}
	for i := range results {
		res := &results[i]
		if res.Package == nil || path.Base(res.Location.URI) != "pom.xml" {
			continue
		}
		coord, ok := versionorder.MavenCoordinate(res.Package.PURL)
		if !ok {
			continue
		}
		scopes, read := poms[res.Location.URI]
		if !read {
			scopes = readPomScopes(dir, res.Location.URI)
			poms[res.Location.URI] = scopes
		}
		switch scopes[coord] {
		case manifests.ScopeProvided:
			if res.Package.Provided {
				continue
			}
			pkg := *res.Package
			pkg.Provided = true
			res.Package = &pkg
		case manifests.ScopeTest:
			if res.Package.Dev {
				continue
			}
			pkg := *res.Package
			pkg.Dev = true
			res.Package = &pkg
		}
	}
}

// readPomScopes reads the scopes of the pom at a repository-relative path in the checkout, or none
// where the path leaves the checkout or the file cannot be read or parsed.
func readPomScopes(dir, rel string) map[string]manifests.Scope {
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel))) // #nosec G304 -- a local path inside the checkout
	if err != nil {
		return nil
	}
	scopes, err := manifests.PomScopes(data)
	if err != nil {
		return nil
	}
	return scopes
}
