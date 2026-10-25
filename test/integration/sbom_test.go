//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// Draugr runs Syft to write SBOMs. It builds Syft's command line, names each document after its
// source, removes the temporary checkout from what comes back and, for a project document, reads
// Syft's CycloneDX to assemble one bill of materials for the release. The unit tests stub Syft, so
// they prove the command line and the assembly over recorded documents and nothing about the build
// `draugr tools install` pins, which these tests run.
//
// The fixtures declare their dependencies at exact versions, so what each document has to contain
// is known by construction rather than read from a database that moves.
const (
	requestsPURL = "pkg:pypi/requests@2.19.1"
	lodashPURL   = "pkg:npm/lodash@4.17.20"
	// The image the provenance tests already pull: public, small, and an operating system whose
	// packages Syft reads from the image rather than from a manifest.
	sbomImage = "docker.io/library/alpine:3.19"
	// busybox is in every Alpine image. Its version moves with the tag, so the test asserts that
	// one is recorded rather than which.
	busyboxPURLPrefix = "pkg:apk/alpine/busybox@"
	// The prefix git.Checkout gives every clone. A document that still carries it differs on every
	// run of the same commit.
	checkoutPrefix = "draugr-repo-"
)

// npmLock is a lockfile naming one package at one version.
const npmLock = `{
  "name": "web",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "web", "dependencies": {"lodash": "4.17.20"}},
    "node_modules/lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    }
  }
}
`

// cdxDocument is as much of a CycloneDX document as these tests read.
type cdxDocument struct {
	BOMFormat string `json:"bomFormat"`
	Metadata  struct {
		Component struct {
			BOMRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	} `json:"metadata"`
	Components   []cdxPackage `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

// cdxPackage is one entry in a CycloneDX document's components.
type cdxPackage struct {
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// lists reports whether the document carries a package whose purl starts with prefix, and that
// package has a version.
func (d cdxDocument) lists(prefix string) bool {
	return slices.ContainsFunc(d.Components, func(c cdxPackage) bool {
		return strings.HasPrefix(c.PURL, prefix) && c.Version != ""
	})
}

// requireNoScanErrors fails the test when report.json records anything that could not run. SBOM
// generation is evidence rather than a control, so a failure of it is recorded under the "(sbom)"
// entry in the controls list, and success is that entry's absence.
func requireNoScanErrors(t *testing.T, outDir string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(outDir, "report.json")) // #nosec G304 -- a file the scan just wrote into t.TempDir()
	if err != nil {
		t.Fatalf("read report.json: %v", err)
	}
	var doc struct {
		Controls []struct {
			Name       string   `json:"name"`
			ScanErrors []string `json:"scanErrors"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse report.json: %v", err)
	}
	for _, c := range doc.Controls {
		if len(c.ScanErrors) > 0 {
			t.Errorf("%s could not run: %v", c.Name, c.ScanErrors)
		}
	}
}

// TestSyftInventoriesEveryTarget takes an inventory of two repositories and an image with
// config.sbom set, and reads back what the scan wrote: one document per target holding that
// target's packages and no other's, and a project document assembled from all three.
//
// Two repositories in one component, because a document named or keyed on the component is right
// with one repository and has the second overwrite the first. The image is the other source Syft
// reads, from a registry rather than a checkout.
func TestSyftInventoriesEveryTarget(t *testing.T) {
	requireTool(t, "syft", "the documents under test are the ones the pinned Syft writes")
	requireTool(t, "git", "the scan checks each repository out before taking its inventory")

	api := newRepo(t, map[string]string{"requirements.txt": "requests==2.19.1\n"})
	web := newRepo(t, map[string]string{"package-lock.json": npmLock})
	dir := t.TempDir()
	writeFile(t, dir, "draugr.saga.yaml", fmt.Sprintf(`project: sbom-integration
release: {version: "1.0.0"}
config:
  sbom:
    enabled: true
    # both: the documents Syft wrote, and the one Draugr assembled from them, in one run.
    scope: both
components:
  - name: app
    repositories:
      - url: %s
      - url: %s
  - name: base
    images:
      - image: %s
`, api, web, sbomImage))

	out, console := scanWith(t, dir, "draugr.saga.yaml", "--evidence")
	requireNoScanErrors(t, out)
	if !strings.Contains(console, "1 project document + 3 component documents (cyclonedx-json)") {
		t.Errorf("the evidence block should account for every document the run wrote:\n%s", console)
	}

	paths, err := filepath.Glob(filepath.Join(out, "sbom-*.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]cdxDocument{}
	for _, path := range paths {
		raw, err := os.ReadFile(path) // #nosec G304 -- a file the scan just wrote into t.TempDir()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), checkoutPrefix) {
			t.Errorf("%s still names the temporary checkout, so two runs of one commit write two "+
				"different documents", filepath.Base(path))
		}
		var doc cdxDocument
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s is not readable CycloneDX: %v", filepath.Base(path), err)
		}
		if doc.BOMFormat != "CycloneDX" {
			t.Errorf("%s has bomFormat %q, want CycloneDX", filepath.Base(path), doc.BOMFormat)
		}
		docs[filepath.Base(path)] = doc
	}
	project, ok := docs["sbom-project.cdx.json"]
	if !ok {
		t.Fatalf("scope: both wrote no project document, only %v", slices.Sorted(maps.Keys(docs)))
	}
	delete(docs, "sbom-project.cdx.json")
	if len(docs) != 3 {
		t.Fatalf("want one document per target, two repositories and an image, got %v",
			slices.Sorted(maps.Keys(docs)))
	}

	// Each package in exactly one target's document. A package in two would mean one inventory
	// was written under two names; a package in none, that a target's inventory was lost.
	holders := map[string]string{}
	for _, want := range []string{requestsPURL, lodashPURL, busyboxPURLPrefix} {
		var in []string
		for name, doc := range docs {
			if doc.lists(want) {
				in = append(in, name)
			}
		}
		if len(in) != 1 {
			t.Errorf("%s should be in exactly one target's document, found in %v", want, in)
			continue
		}
		holders[want] = in[0]
	}
	if len(holders) == 3 && (holders[requestsPURL] == holders[lodashPURL] ||
		holders[busyboxPURLPrefix] == holders[requestsPURL] ||
		holders[busyboxPURLPrefix] == holders[lodashPURL]) {
		t.Errorf("two targets share one document: %v", holders)
	}

	// The project document is Draugr's own, built by reading what Syft wrote. A change in how Syft
	// identifies a package or a source reaches it here and nowhere else.
	if project.Metadata.Component.Name != "sbom-integration" || project.Metadata.Component.Version != "1.0.0" {
		t.Errorf("the project document should describe the release, got %+v", project.Metadata.Component)
	}
	for _, want := range []string{requestsPURL, lodashPURL, busyboxPURLPrefix} {
		if !project.lists(want) {
			t.Errorf("the project document lost %s on assembly", want)
		}
	}
	graph := map[string][]string{}
	for _, d := range project.Dependencies {
		graph[d.Ref] = append(graph[d.Ref], d.DependsOn...)
	}
	reaches := func(component string) []string {
		var held []string
		for _, target := range graph["draugr:component/"+component] {
			held = append(held, graph[target]...)
		}
		return held
	}
	if targets := graph["draugr:component/app"]; len(targets) != 2 {
		t.Errorf("component app should hold its two repositories, holds %v", targets)
	}
	for _, want := range []string{requestsPURL, lodashPURL} {
		if !slices.Contains(reaches("app"), want) {
			t.Errorf("nothing under component app holds %s, so the graph cannot say who ships it", want)
		}
	}
	if !slices.ContainsFunc(reaches("base"), func(ref string) bool { return strings.HasPrefix(ref, busyboxPURLPrefix) }) {
		t.Errorf("nothing under component base holds busybox, so the graph cannot say who ships it")
	}
	known := map[string]bool{project.Metadata.Component.BOMRef: true}
	for _, c := range project.Components {
		known[c.BOMRef] = true
	}
	for ref, targets := range graph {
		for _, r := range append([]string{ref}, targets...) {
			if !known[r] {
				t.Errorf("the project graph names %s, which the document does not contain; a consumer "+
					"walking it loses whatever is behind that edge", r)
			}
		}
	}
}

// TestSyftWritesEveryFormatDraugrOffers runs each format the descriptor accepts through the pinned
// Syft. Draugr hands the name to Syft's -o as it is, so a format renamed upstream is a documented
// option that stops working, and only a real run would show it.
func TestSyftWritesEveryFormatDraugrOffers(t *testing.T) {
	requireTool(t, "syft", "the formats under test are the ones the pinned Syft accepts")
	requireTool(t, "git", "the scan checks the repository out before taking its inventory")

	repo := newRepo(t, map[string]string{"requirements.txt": "requests==2.19.1\n"})
	for _, format := range saga.SBOMFormats {
		t.Run(string(format), func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "draugr.saga.yaml", fmt.Sprintf(`project: sbom-formats
release: {version: "1.0.0"}
config:
  sbom: {enabled: true, format: %s}
components:
  - name: api
    repositories:
      - url: %s
`, format, repo))

			out := scanTo(t, dir, "draugr.saga.yaml")
			requireNoScanErrors(t, out)
			paths, err := filepath.Glob(filepath.Join(out, "sbom-*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(paths) != 1 {
				t.Fatalf("want one document for one repository, got %v", paths)
			}
			raw, err := os.ReadFile(paths[0]) // #nosec G304 -- a file the scan just wrote into t.TempDir()
			if err != nil {
				t.Fatal(err)
			}
			// Every format carries the purl, whatever else differs between them.
			if !strings.Contains(string(raw), requestsPURL) {
				t.Errorf("%s does not list %s:\n%s", filepath.Base(paths[0]), requestsPURL, raw)
			}
			if strings.Contains(string(raw), checkoutPrefix) {
				t.Errorf("%s still names the temporary checkout", filepath.Base(paths[0]))
			}
			if strings.HasSuffix(paths[0], ".json") && !json.Valid(raw) {
				t.Errorf("%s is not valid JSON", filepath.Base(paths[0]))
			}
		})
	}
}
