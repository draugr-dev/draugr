package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// syftSBOM is what Syft actually produces, trimmed: the manifest recorded in Syft's own namespace,
// the packager implicit in the purl, and structural components carrying neither.
const syftSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "metadata": {"component": {"type": "file", "name": "."}},
  "components": [
    {"type": "application", "name": "reporting-api"},
    {"type": "library", "name": "flask", "version": "0.12.2",
     "purl": "pkg:pypi/flask@0.12.2",
     "properties": [
       {"name": "syft:package:language", "value": "python"},
       {"name": "syft:location:0:path", "value": "/requirements.txt"}
     ]},
    {"type": "library", "name": "rails", "version": "7.1.0",
     "purl": "pkg:gem/rails@7.1.0",
     "properties": [{"name": "syft:location:0:path", "value": "/api/Gemfile.lock"}]},
    {"type": "file", "name": "requirements.txt"}
  ]
}`

func gitlabSBOMData(docs ...sbom.Document) Data {
	d := gitlabData()
	d.Run.SBOMs = docs
	return d
}

func renderGitLabSBOM(t *testing.T, d Data) map[string]any {
	t.Helper()
	var b bytes.Buffer
	if err := (gitlabSBOMReporter{}).Render(&b, d); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatalf("the rendered SBOM is not valid JSON: %v", err)
	}
	return out
}

// The two facts GitLab needs are already in the SBOM under other names.
func TestGitLabSBOMTranslatesWhatGitLabReads(t *testing.T) {
	doc := renderGitLabSBOM(t, gitlabSBOMData(sbom.Document{
		Project: true, Format: saga.SBOMCycloneDXJSON, Bytes: []byte(syftSBOM),
	}))

	// GitLab reads 1.4, 1.5 and 1.6 and rejects anything else outright — a 1.7 document is not
	// partially understood, it is "could not be parsed", and every surface built on it stays empty.
	if got := doc["specVersion"]; got != gitlabSBOMSpecVersion {
		t.Errorf("specVersion = %v, want %s", got, gitlabSBOMSpecVersion)
	}

	byName := map[string]map[string]string{}
	for _, raw := range doc["components"].([]any) {
		c := raw.(map[string]any)
		props := map[string]string{}
		for _, p := range c["properties"].([]any) {
			pm := p.(map[string]any)
			props[pm["name"].(string)] = pm["value"].(string)
		}
		byName[c["name"].(string)] = props
	}

	cases := []struct{ pkg, manager, file string }{
		{"flask", "pip", "requirements.txt"},
		{"rails", "bundler", "api/Gemfile.lock"},
	}
	for _, tc := range cases {
		props, ok := byName[tc.pkg]
		if !ok {
			t.Errorf("%s is missing from the document", tc.pkg)
			continue
		}
		if got := props["gitlab:dependency_scanning:package_manager:name"]; got != tc.manager {
			t.Errorf("%s packager = %q, want %q", tc.pkg, got, tc.manager)
		}
		// Repository-relative: Syft records "/requirements.txt" and GitLab wants it without the
		// leading slash, or the location does not resolve to a file in the repository.
		if got := props["gitlab:dependency_scanning:input_file:path"]; got != tc.file {
			t.Errorf("%s input file = %q, want %q", tc.pkg, got, tc.file)
		}
		// Syft's own properties are kept: this is a translation, not a replacement, and a
		// consumer that reads them should still find them.
		if props["syft:location:0:path"] == "" && tc.pkg == "flask" {
			t.Error("translating dropped the property it translated from")
		}
	}
}

// An SBOM describes the tree it was taken from as well as the packages in it.
func TestGitLabSBOMKeepsOnlyPackages(t *testing.T) {
	doc := renderGitLabSBOM(t, gitlabSBOMData(sbom.Document{
		Project: true, Format: saga.SBOMCycloneDXJSON, Bytes: []byte(syftSBOM),
	}))
	names := []string{}
	for _, raw := range doc["components"].([]any) {
		names = append(names, raw.(map[string]any)["name"].(string))
	}
	if len(names) != 2 {
		t.Errorf("components = %v, want only the two packages", names)
	}
	for _, unwanted := range []string{"reporting-api", "requirements.txt"} {
		for _, got := range names {
			if got == unwanted {
				t.Errorf("%q has no purl and no version; as a dependency row it names a file", unwanted)
			}
		}
	}
}

// The assembled document covers every component in one file, which is what the dependency list is
// a view of. A per-target document is the fallback.
func TestGitLabSBOMPrefersTheAssembledDocument(t *testing.T) {
	perTarget := sbom.Document{
		Component: "api", Format: saga.SBOMCycloneDXJSON,
		Bytes: []byte(`{"specVersion":"1.7","components":[
			{"name":"only-mine","version":"1","purl":"pkg:npm/only-mine@1"}]}`),
	}
	project := sbom.Document{
		Project: true, Format: saga.SBOMCycloneDXJSON, Bytes: []byte(syftSBOM),
	}

	doc := renderGitLabSBOM(t, gitlabSBOMData(perTarget, project))
	for _, raw := range doc["components"].([]any) {
		if raw.(map[string]any)["name"] == "only-mine" {
			t.Fatal("rendered a per-target document while an assembled one was available")
		}
	}

	// With no assembled document, the per-target one is what there is.
	doc = renderGitLabSBOM(t, gitlabSBOMData(perTarget))
	if doc["components"].([]any)[0].(map[string]any)["name"] != "only-mine" {
		t.Error("the per-target document was not used as the fallback")
	}
}

// A report with nothing behind it is a green tick that means nothing.
func TestGitLabSBOMSaysWhenThereIsNoSBOM(t *testing.T) {
	cases := []struct {
		name string
		docs []sbom.Document
		want string
	}{
		{"config.sbom not enabled", nil, "config.sbom"},
		{
			"a format GitLab cannot read",
			[]sbom.Document{{Project: true, Format: saga.SBOMSPDXJSON, Bytes: []byte(`{}`)}},
			"config.sbom",
		},
		{
			"an SBOM of the tree with no packages in it",
			[]sbom.Document{{Project: true, Format: saga.SBOMCycloneDXJSON,
				Bytes: []byte(`{"specVersion":"1.6","components":[{"type":"file","name":"go.mod"}]}`)}},
			"no packages",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (gitlabSBOMReporter{}).Render(&bytes.Buffer{}, gitlabSBOMData(tc.docs...))
			if err == nil {
				t.Fatal("an empty document was written and GitLab would show it as a clean project")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error should name what is missing: %v", err)
			}
		})
	}
}

func TestGitLabPackageManagerReadsThePurlType(t *testing.T) {
	// Mapped only where the vocabularies differ; anything else passes through, because a purl type
	// is already an ecosystem name and a blank column is worse than one naming the ecosystem.
	cases := map[string]string{
		"pkg:pypi/flask@0.12.2":       "pip",
		"pkg:gem/rails@7.1.0":         "bundler",
		"pkg:golang/gorm.io/gorm@1.2": "go",
		"pkg:npm/express@4":           "npm",
		"pkg:cargo/serde@1":           "cargo",
		"pkg:deb/debian/libc6@2.36":   "deb",
		"not-a-purl":                  "",
		"pkg:":                        "",
	}
	for purl, want := range cases {
		if got := gitlabPackageManager(purl); got != want {
			t.Errorf("gitlabPackageManager(%q) = %q, want %q", purl, got, want)
		}
	}
}

// GitLab's own analyzers emit one SBOM per manifest and name it at document level; Draugr emits one
// covering everything. Where the two shapes agree — every package from the same file — saying so is
// what fills the dependency list's Location column.
func TestGitLabSBOMNamesTheManifestWhenThereIsOnlyOne(t *testing.T) {
	oneFile := `{"specVersion":"1.6","components":[
		{"name":"flask","version":"0.12.2","purl":"pkg:pypi/flask@0.12.2",
		 "properties":[{"name":"syft:location:0:path","value":"/requirements.txt"}]},
		{"name":"urllib3","version":"1.24.1","purl":"pkg:pypi/urllib3@1.24.1",
		 "properties":[{"name":"syft:location:0:path","value":"/requirements.txt"}]}]}`

	doc := renderGitLabSBOM(t, gitlabSBOMData(sbom.Document{
		Project: true, Format: saga.SBOMCycloneDXJSON, Bytes: []byte(oneFile),
	}))
	meta, _ := doc["metadata"].(map[string]any)
	if meta == nil {
		t.Fatal("no metadata, so GitLab has no document-level path to read")
	}
	if got := gitlabPropertyValue(meta["properties"].([]any), gitlabInputFileProperty); got != "requirements.txt" {
		t.Errorf("metadata input file = %q, want requirements.txt", got)
	}
}

// With several manifests there is no single answer, and inventing one attributes a package to a
// file that does not declare it. The per-component paths still stand.
func TestGitLabSBOMWillNotGuessBetweenManifests(t *testing.T) {
	doc := renderGitLabSBOM(t, gitlabSBOMData(sbom.Document{
		Project: true, Format: saga.SBOMCycloneDXJSON, Bytes: []byte(syftSBOM),
	}))
	meta, _ := doc["metadata"].(map[string]any)
	metaProps, _ := meta["properties"].([]any)
	if got := gitlabPropertyValue(metaProps, gitlabInputFileProperty); got != "" {
		t.Errorf("two manifests and the document claims one of them: %q", got)
	}
	// Each package still says where it came from.
	for _, raw := range doc["components"].([]any) {
		c := raw.(map[string]any)
		props, _ := c["properties"].([]any)
		if gitlabPropertyValue(props, gitlabInputFileProperty) == "" {
			t.Errorf("%v lost its own manifest path", c["name"])
		}
	}
}
