package sbom

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// cdxDoc builds a per-target CycloneDX document the way syft would emit one.
func cdxDoc(rootRef string, comps ...cdxComponent) []byte {
	d := cycloneDX{
		BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Metadata:   cdxMetadata{Component: &cdxComponent{Type: "file", Name: "src", BOMRef: rootRef}},
		Components: comps,
	}
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return b
}

func pkg(name, version, purl, ref string) cdxComponent {
	return cdxComponent{Type: "library", Name: name, Version: version, PURL: purl, BOMRef: ref}
}

func doc(component, target string, bytes []byte) sbom.Document {
	return sbom.Document{Component: component, Target: target, Format: saga.SBOMCycloneDXJSON, Bytes: bytes}
}

// parse reads an assembled document back so assertions are about what a consumer sees.
func parse(t *testing.T, d sbom.Document) cycloneDX {
	t.Helper()
	var got cycloneDX
	if err := json.Unmarshal(d.Bytes, &got); err != nil {
		t.Fatalf("assembled document is not valid JSON: %v", err)
	}
	return got
}

func release() saga.Release { return saga.Release{Name: "acme-platform", Version: "3.1.0"} }

func assemble(t *testing.T, docs ...sbom.Document) cycloneDX {
	t.Helper()
	out, err := New().Assemble(release(), saga.SBOMCycloneDXJSON, docs)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if !out.Project {
		t.Error("assembled document is not marked as the project document")
	}
	return parse(t, out)
}

// dependsOn returns the graph edge for ref, or nil.
func dependsOn(d cycloneDX, ref string) []string {
	for _, dep := range d.Dependencies {
		if dep.Ref == ref {
			return dep.DependsOn
		}
	}
	return nil
}

func TestAssembleRootIsTheRelease(t *testing.T) {
	got := assemble(t, doc("api", "repo-a", cdxDoc("root-a", pkg("requests", "2.19.1", "pkg:pypi/requests@2.19.1", "r1"))))

	root := got.Metadata.Component
	if root == nil || root.Name != "acme-platform" || root.Version != "3.1.0" {
		t.Fatalf("root component = %+v, want the release", root)
	}
	if root.Type != "application" {
		t.Errorf("root type = %q, want application", root.Type)
	}
	if got.BOMFormat != "CycloneDX" || got.SpecVersion != assembledSpecVersion {
		t.Errorf("envelope = %s %s", got.BOMFormat, got.SpecVersion)
	}
}

// The hierarchy is the whole reason this is assembly rather than a merge: release contains
// components, components contain targets, targets contain packages.
func TestAssembleBuildsTheDeclaredHierarchy(t *testing.T) {
	got := assemble(t,
		doc("api", "repo-a", cdxDoc("root-a", pkg("requests", "2.19.1", "pkg:pypi/requests@2.19.1", "r1"))),
		doc("api", "repo-b", cdxDoc("root-b", pkg("flask", "0.12.2", "pkg:pypi/flask@0.12.2", "f1"))),
		doc("worker", "repo-c", cdxDoc("root-c", pkg("pyyaml", "5.1", "pkg:pypi/pyyaml@5.1", "y1"))),
	)

	if want := []string{"draugr:component/api", "draugr:component/worker"}; !equal(dependsOn(got, "draugr:release/acme-platform"), want) {
		t.Errorf("release depends on %v, want %v", dependsOn(got, "draugr:release/acme-platform"), want)
	}
	if want := []string{"draugr:target/api/repo-a", "draugr:target/api/repo-b"}; !equal(dependsOn(got, "draugr:component/api"), want) {
		t.Errorf("api depends on %v, want %v", dependsOn(got, "draugr:component/api"), want)
	}
	if want := []string{"pkg:pypi/requests@2.19.1"}; !equal(dependsOn(got, "draugr:target/api/repo-a"), want) {
		t.Errorf("repo-a depends on %v, want %v", dependsOn(got, "draugr:target/api/repo-a"), want)
	}
}

// The trap the design exists to avoid. One entry per package answers "what do we ship"; the graph
// answers "who ships it". Collapsing to one entry without the graph loses the second question,
// which is the one a triager asks the moment a CVE lands.
func TestAssembleKeepsOnePackageEntryAndBothContainers(t *testing.T) {
	shared := "pkg:pypi/requests@2.19.1"
	got := assemble(t,
		doc("api", "repo-a", cdxDoc("root-a", pkg("requests", "2.19.1", shared, "r1"))),
		doc("worker", "repo-c", cdxDoc("root-c", pkg("requests", "2.19.1", shared, "r2"))),
	)

	n := 0
	for _, c := range got.Components {
		if c.PURL == shared {
			n++
		}
	}
	if n != 1 {
		t.Errorf("requests appears %d times, want one entry", n)
	}
	for _, target := range []string{"draugr:target/api/repo-a", "draugr:target/worker/repo-c"} {
		if !contains(dependsOn(got, target), shared) {
			t.Errorf("%s does not contain requests; provenance was lost in the dedup", target)
		}
	}
}

// Two versions of one library are two packages. Merging them would claim the project ships a
// version it does not, and would attach one version's vulnerabilities to the other's consumer.
func TestAssembleKeepsDistinctVersionsDistinct(t *testing.T) {
	got := assemble(t,
		doc("api", "repo-a", cdxDoc("root-a", pkg("jinja2", "2.10", "pkg:pypi/jinja2@2.10", "j1"))),
		doc("worker", "repo-c", cdxDoc("root-c", pkg("jinja2", "2.8", "pkg:pypi/jinja2@2.8", "j2"))),
	)
	seen := map[string]bool{}
	for _, c := range got.Components {
		if c.Name == "jinja2" {
			seen[c.Version] = true
		}
	}
	if len(seen) != 2 {
		t.Errorf("jinja2 versions = %v, want both 2.8 and 2.10", seen)
	}
}

// A package with no purl still must not merge with a different version of itself. The fallback
// key is a digest over the identifying fields for exactly this reason.
func TestAssembleDoesNotMergeUnidentifiedPackagesOfDifferentVersions(t *testing.T) {
	got := assemble(t,
		doc("api", "repo-a", cdxDoc("root-a", pkg("mylib", "1.0", "", "m1"))),
		doc("worker", "repo-c", cdxDoc("root-c", pkg("mylib", "2.0", "", "m2"))),
	)
	n := 0
	for _, c := range got.Components {
		if c.Name == "mylib" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("mylib entries = %d, want 2 — different versions must not collapse", n)
	}
}

func TestAssembleDedupesAnIdenticalUnidentifiedPackage(t *testing.T) {
	got := assemble(t,
		doc("api", "repo-a", cdxDoc("root-a", pkg("mylib", "1.0", "", "m1"))),
		doc("worker", "repo-c", cdxDoc("root-c", pkg("mylib", "1.0", "", "m2"))),
	)
	n := 0
	for _, c := range got.Components {
		if c.Name == "mylib" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("mylib entries = %d, want 1", n)
	}
}

// Packages are re-keyed on assembly, so the source's own edges have to be translated. An
// untranslated edge points at an identifier that is not in the document, and a consumer walking
// the graph silently loses everything behind it.
func TestAssembleTranslatesSourceDependencyEdges(t *testing.T) {
	src := cycloneDX{
		BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Metadata: cdxMetadata{Component: &cdxComponent{Type: "file", Name: "src", BOMRef: "root-a"}},
		Components: []cdxComponent{
			pkg("flask", "0.12.2", "pkg:pypi/flask@0.12.2", "f1"),
			pkg("jinja2", "2.8", "pkg:pypi/jinja2@2.8", "j1"),
		},
		Dependencies: []cdxDependency{{Ref: "f1", DependsOn: []string{"j1"}}},
	}
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	got := assemble(t, doc("api", "repo-a", b))

	if want := []string{"pkg:pypi/jinja2@2.8"}; !equal(dependsOn(got, "pkg:pypi/flask@0.12.2"), want) {
		t.Errorf("flask depends on %v, want %v", dependsOn(got, "pkg:pypi/flask@0.12.2"), want)
	}
	assertNoDanglingRefs(t, got)
}

func assertNoDanglingRefs(t *testing.T, d cycloneDX) {
	t.Helper()
	known := map[string]bool{d.Metadata.Component.BOMRef: true}
	for _, c := range d.Components {
		known[c.BOMRef] = true
	}
	for _, dep := range d.Dependencies {
		if !known[dep.Ref] {
			t.Errorf("dependency ref %q is not a component in the document", dep.Ref)
		}
		for _, target := range dep.DependsOn {
			if !known[target] {
				t.Errorf("%q depends on %q, which is not in the document", dep.Ref, target)
			}
		}
	}
}

// A project SBOM is an artifact people commit and diff between releases. If regenerating it
// reorders the graph, every regeneration reads as a change and nobody reads the diffs.
func TestAssembleIsDeterministic(t *testing.T) {
	in := []sbom.Document{
		doc("worker", "repo-c", cdxDoc("root-c", pkg("pyyaml", "5.1", "pkg:pypi/pyyaml@5.1", "y1"))),
		doc("api", "repo-a", cdxDoc("root-a",
			pkg("requests", "2.19.1", "pkg:pypi/requests@2.19.1", "r1"),
			pkg("urllib3", "1.24.1", "pkg:pypi/urllib3@1.24.1", "u1"))),
	}
	first, err := New().Assemble(release(), saga.SBOMCycloneDXJSON, in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := New().Assemble(release(), saga.SBOMCycloneDXJSON, in)
		if err != nil {
			t.Fatal(err)
		}
		if string(again.Bytes) != string(first.Bytes) {
			t.Fatal("two assemblies of the same input differ")
		}
	}
}

// SPDX can express containment, but assembling it correctly is different work. Emitting a
// half-right SPDX document would be worse than declining, because nothing about it looks wrong.
func TestAssembleRefusesAFormatItCannotAssemble(t *testing.T) {
	for _, f := range []saga.SBOMFormat{saga.SBOMSPDXJSON, saga.SBOMSPDXTagValue, saga.SBOMCycloneDXXML} {
		_, err := New().Assemble(release(), f, []sbom.Document{doc("api", "repo-a", cdxDoc("root-a"))})
		if err == nil {
			t.Fatalf("format %s was accepted", f)
		}
		if !strings.Contains(err.Error(), "cyclonedx-json") || !strings.Contains(err.Error(), "scope: component") {
			t.Errorf("error should name the format to use and the way out, got: %v", err)
		}
	}
}

func TestAssembleDefaultsAnEmptyFormat(t *testing.T) {
	if _, err := New().Assemble(release(), "", []sbom.Document{doc("api", "repo-a", cdxDoc("root-a"))}); err != nil {
		t.Errorf("empty format should resolve to the default: %v", err)
	}
}

func TestAssembleRefusesWithNothingToAssemble(t *testing.T) {
	if _, err := New().Assemble(release(), saga.SBOMCycloneDXJSON, nil); err == nil {
		t.Error("assembling nothing should be an error")
	}
}

// A document that cannot be read is named, so the failure points at the target to look at rather
// than at the assembly step.
func TestAssembleNamesTheDocumentItCannotRead(t *testing.T) {
	_, err := New().Assemble(release(), saga.SBOMCycloneDXJSON,
		[]sbom.Document{doc("api", "repo-a", []byte("not json"))})
	if err == nil {
		t.Fatal("unreadable document was accepted")
	}
	if !strings.Contains(err.Error(), "api") || !strings.Contains(err.Error(), "repo-a") {
		t.Errorf("error should name the document, got: %v", err)
	}
}

// The target node takes its type from the source document, so an image reads as a container
// rather than being flattened into "application".
func TestAssembleTargetNodeKeepsTheSourceType(t *testing.T) {
	src := cycloneDX{
		BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Metadata: cdxMetadata{Component: &cdxComponent{Type: "container", Name: "img", BOMRef: "root-i"}},
	}
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	got := assemble(t, doc("api", "acme/api:1.0", b))
	for _, c := range got.Components {
		if c.BOMRef == "draugr:target/api/acme/api:1.0" && c.Type != "container" {
			t.Errorf("target node type = %q, want container", c.Type)
		}
	}
}

func equal(a, b []string) bool { return slices.Equal(a, b) }

func contains(hay []string, needle string) bool { return slices.Contains(hay, needle) }
