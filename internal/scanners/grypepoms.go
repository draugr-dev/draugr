package scanners

import (
	"os"
	"path"
	"path/filepath"
	"slices"

	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/internal/versionorder"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// spreadPomFindings gives every pom.xml that declares a vulnerable Maven package the finding Grype
// reported for it in one pom only, and counts the package as read there.
//
// Syft lists a package declared identically by several poms once, with one location, in every
// format it writes, so Grype names one pom for a flaw that each of them must upgrade, and the
// others show fewer packages read than they declare. The inventory still lists each pom Grype read,
// because each pom's own artifact is a package located in it. A pom in that list whose dependencies
// declare the same groupId:artifactId at the same version takes a copy of the finding.
//
// The version is read from the pom itself (manifests.PomVersions). A pom whose version for the
// package comes from a parent or a BOM is not given a copy, because nothing in this checkout says
// which version it resolves to.
//
// Before markPomScopes, so each copy takes the scope of the pom it now names, and after the paths
// are repository-relative, which both the results and the inventory are by then.
func spreadPomFindings(report *sarif.Report, dir string) {
	var poms []int
	for i, in := range report.Inputs {
		if path.Base(in.Path) == "pom.xml" {
			poms = append(poms, i)
		}
	}
	if len(poms) < 2 {
		return
	}
	versions := map[string]map[string][]string{}
	versionsOf := func(rel string) map[string][]string {
		v, read := versions[rel]
		if !read {
			v = readPomVersions(dir, rel)
			versions[rel] = v
		}
		return v
	}
	// Where Grype itself named a package in a pom, it read it there, and that pom needs nothing.
	type at struct{ purl, pom string }
	listed := map[at]bool{}
	for _, r := range report.Results {
		if r.Package != nil {
			listed[at{r.Package.PURL, r.Location.URI}] = true
		}
	}
	spread := map[at]bool{}
	for _, r := range slices.Clone(report.Results) {
		if r.Package == nil || path.Base(r.Location.URI) != "pom.xml" {
			continue
		}
		coord, ok := versionorder.MavenCoordinate(r.Package.PURL)
		if !ok || r.Package.Version == "" {
			continue
		}
		for _, i := range poms {
			pom := report.Inputs[i].Path
			k := at{r.Package.PURL, pom}
			if listed[k] || !slices.Contains(versionsOf(pom)[coord], r.Package.Version) {
				continue
			}
			// One count per package and pom, however many advisories name it.
			if !spread[k] {
				spread[k] = true
				report.Inputs[i].Packages++
			}
			cp := r
			pkg := *r.Package
			cp.Package = &pkg
			cp.Location.URI = pom
			report.Results = append(report.Results, cp)
		}
	}
}

// readPomVersions reads the dependency versions of the pom at a repository-relative path in the
// checkout, or none where the path leaves the checkout or the file cannot be read or parsed.
func readPomVersions(dir, rel string) map[string][]string {
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel))) // #nosec G304 -- a local path inside the checkout
	if err != nil {
		return nil
	}
	v, err := manifests.PomVersions(data)
	if err != nil {
		return nil
	}
	return v
}
