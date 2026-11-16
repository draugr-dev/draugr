package saga

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The JSON Schema is generated from this package's types by internal/schemagen, which also covers
// every field by construction: a descriptor struct or field it cannot describe fails generation,
// and TestCheckedInSchemaIsUpToDate there fails when this file differs from what it generates. The
// tests here hold the schema to the loader on the cases people meet.
const schemaPath = "draugr.saga.schema.json"

const fragmentSchemaPath = "draugr.saga-fragment.schema.json"

func loadSchema(t *testing.T) map[string]any { return readSchema(t, schemaPath) }

func readSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	return doc
}

// definitionFor finds the $defs entry describing a Go struct, by the name we gave it.
func definitionFor(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	defs, _ := doc["$defs"].(map[string]any)
	if name == "" { // the root document
		return doc
	}
	def, ok := defs[name].(map[string]any)
	if !ok {
		t.Fatalf("schema has no $defs.%s", name)
	}
	return def
}

// The enums are what make editor completion useful; they must match the constants.
func TestSchemaEnumsMatchConstants(t *testing.T) {
	doc := loadSchema(t)

	check := func(defName string, want []string) {
		t.Helper()
		def := definitionFor(t, doc, defName)
		variants, ok := def["anyOf"].([]any)
		if !ok {
			t.Fatalf("%s: expected anyOf variants", defName)
		}
		got := map[string]bool{}
		for _, v := range variants {
			m, _ := v.(map[string]any)
			if c, ok := m["const"].(string); ok {
				got[c] = true
			}
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("%s: schema is missing %q", defName, w)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s: schema lists %d values, the model defines %d", defName, len(got), len(want))
		}
	}

	check("exposure", []string{
		string(ExposurePublic), string(ExposureAuthenticated),
		string(ExposureInternal), string(ExposureRestricted),
	})
	check("criticality", []string{
		string(CriticalityCritical), string(CriticalityImportant), string(CriticalitySupporting),
	})
}

// An editor that accepts an item field validation refuses tells the reader the descriptor is fine
// until the run.
func TestSchemaRefusesTheFieldsValidationRefuses(t *testing.T) {
	for _, path := range []string{schemaPath, fragmentSchemaPath} {
		fields, _ := definitionFor(t, readSchema(t, path), "issueItem")["properties"].(map[string]any)["fields"].(map[string]any)
		names, _ := fields["propertyNames"].(map[string]any)
		not, _ := names["not"].(map[string]any)
		enum, _ := not["enum"].([]any)
		got := make([]string, 0, len(enum))
		for _, e := range enum {
			s, _ := e.(string)
			got = append(got, s)
		}
		if !slices.Equal(got, AzureOwnedFields) {
			t.Errorf("%s: item.fields refuses %q, validation refuses %q", path, got, AzureOwnedFields)
		}
	}
}

// A schema that doesn't accept our own examples is worse than none.
func TestSchemaIdIsThePublishedURL(t *testing.T) {
	doc := loadSchema(t)
	const want = "https://draugr.dev/schema/draugr.saga.schema.json"
	if got, _ := doc["$id"].(string); got != want {
		t.Errorf("$id = %q, want %q, editors resolve $ref against it", got, want)
	}
}

// A Saga should be able to name the schema for the exact Draugr that will read it, so an editor
// doesn't autocomplete fields the installed binary rejects.
func TestSchemaURLFor(t *testing.T) {
	cases := map[string]string{
		"0.33.0":  "https://draugr.dev/schema/v0.33.0/draugr.saga.schema.json",
		"v0.33.0": "https://draugr.dev/schema/v0.33.0/draugr.saga.schema.json",
		// Unreleased builds have no published copy; tracking latest is the only sane fallback.
		"dev": SchemaURL,
		"":    SchemaURL,
		" ":   SchemaURL,
	}
	for in, want := range cases {
		if got := SchemaURLFor(in); got != want {
			t.Errorf("SchemaURLFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// The config schema is published beside the Saga's, under the same versions.
func TestConfigSchemaURLFor(t *testing.T) {
	cases := map[string]string{
		"0.33.0":  "https://draugr.dev/schema/v0.33.0/draugr.config.schema.json",
		"v0.33.0": "https://draugr.dev/schema/v0.33.0/draugr.config.schema.json",
		"dev":     ConfigSchemaURL,
		"":        ConfigSchemaURL,
	}
	for in, want := range cases {
		if got := ConfigSchemaURLFor(in); got != want {
			t.Errorf("ConfigSchemaURLFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// The embedded copy is what `draugr schema` prints and what an offline setup validates against;
// it must be the same document the site publishes.
func TestEmbeddedSchemaMatchesFile(t *testing.T) {
	onDisk, err := os.ReadFile(filepath.Clean(schemaPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(SchemaJSON) != string(onDisk) {
		t.Error("the embedded schema differs from schema file on disk")
	}
	var doc map[string]any
	if err := json.Unmarshal(SchemaJSON, &doc); err != nil {
		t.Fatalf("embedded schema is not valid JSON: %v", err)
	}
}

// The published schema and the loader are two validators over the same document. If they ever
// disagree, an editor contradicts the CLI. Which is worse than either being lenient alone. This
// asserts they reject the same things, for the cases people actually hit.
func TestLoaderRejectsWhatTheSchemaRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field at the root": `
project: a
release: {version: "1"}
bogus: true`,
		"unknown field in release": `
project: a
release: {version: "1", bogusField: x}`,
		"unknown field in a component": `
project: a
release: {version: "1"}
components:
  - name: web
    repositores: []`,
		"unknown field in a repository": `
project: a
release: {version: "1"}
components:
  - name: web
    repositories:
      - url: .
        branch: main`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			// additionalProperties:false in the schema. The loader must agree.
			if _, err := Load([]byte(doc)); err == nil {
				t.Error("the loader accepted a document the schema rejects")
			}
		})
	}
}

// A field that used to parse arrives as an unknown one, and "check the spelling" is the wrong
// advice for a line somebody copied from our own reference. The error has to name the removal.
func TestRemovedFieldSaysSo(t *testing.T) {
	_, err := Load([]byte("release: {version: \"1\", stage: dev}\nproject: p"))
	if err == nil {
		t.Fatal("release.stage still parses")
	}
	for _, want := range []string{"release.stage was removed", "nothing read it"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "check the spelling") {
		t.Errorf("removed field got the typo hint: %v", err)
	}
}

// A descriptor written for an earlier release declares its clusters under `infrastructure:`. The
// key is refused, and the error carries the replacement, so the fix is one edit rather than a
// search through the reference. The replacement has to be one the loader accepts, or following the
// advice is a second error.
func TestTheOldClusterKeyNamesItsReplacement(t *testing.T) {
	_, err := Load([]byte("project: p\nrelease: {version: \"1\"}\ncomponents:\n  - name: c\n" +
		"    infrastructure:\n      - kind: kubernetes\n        ref: prod\n"))
	if err == nil {
		t.Fatal("components[].infrastructure still parses")
	}
	for _, want := range []string{"components.infrastructure was removed",
		"`clusters: {prod: {context: prod-eu-west-1}}`", "`kubernetes: [{cluster: prod}]`"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
	if _, err := Load([]byte("project: p\nrelease: {version: \"1\"}\n" +
		"clusters: {prod: {context: prod-eu-west-1}}\ncomponents:\n  - name: c\n" +
		"    kubernetes: [{cluster: prod}]\n")); err != nil {
		t.Errorf("the replacement the error names does not load: %v", err)
	}
}

// …and conversely, that strictness must not reach into scanner options, which are deliberately
// open: each scanner validates its own block against its ConfigSchema when the scan is planned.
func TestScannerOptionsStayFreeForm(t *testing.T) {
	doc := `
project: a
release: {version: "1"}
config:
  controllers:
    sast:
      enabled: true
      semgrep:
        config: p/owasp-top-ten
        someFutureOption: 42
`
	if _, err := Load([]byte(doc)); err != nil {
		t.Errorf("scanner options should not be constrained by the model: %v", err)
	}
}

// The error has to tell a reader which part of their file is wrong.
func TestUnknownFieldErrorNamesTheSection(t *testing.T) {
	_, err := Load([]byte("project: a\nrelease: {version: \"1\", bogusField: x}"))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{`"bogusField"`, "release"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

// TestSchemaDefinitionsAreStrict keeps an unknown key an error rather than a shrug.
//
// A descriptor is how somebody says what to scan, so a mistyped key that validates is a setting
// they believe they made and a control that quietly never ran. additionalProperties:false is what
// turns that into a message at load time.
func TestSchemaDefinitionsAreStrict(t *testing.T) {
	t.Parallel()
	// Both files. The fragment schema is generated from this one and byte-compared to the copy in
	// the tree, so a transform that dropped strictness on the way would leave the saga schema
	// strict, the comparison green, and fragments accepting anything.
	for _, path := range []string{schemaPath, fragmentSchemaPath} {
		t.Run(path, func(t *testing.T) { assertStrict(t, readSchema(t, path)) })
	}
}

func assertStrict(t *testing.T, doc map[string]any) {
	t.Helper()

	// Nothing is exempt any more. `controllers` used to be a map whose values were a generic
	// per-scanner schema; it now enumerates the controls this build serves, each with its own
	// definition, so an unknown control name is a schema error rather than a shape that validates
	// and then fails at load.
	openByDesign := map[string]string{}

	if doc["additionalProperties"] != false {
		t.Error("the root document accepts unknown keys")
	}
	defs, _ := doc["$defs"].(map[string]any)
	for name, raw := range defs {
		def, ok := raw.(map[string]any)
		if !ok || def["type"] != "object" {
			continue
		}
		if reason := openByDesign[name]; reason != "" {
			if def["additionalProperties"] == false {
				t.Errorf("$defs.%s is %s and must describe its values, not forbid them", name, reason)
			}
			continue
		}
		if def["additionalProperties"] != false {
			t.Errorf("$defs.%s accepts unknown keys. Add \"additionalProperties\": false so a "+
				"mistyped key is reported rather than silently accepted", name)
		}
	}
}

// A fragment's component is refused `controls` by the loader, so its schema must not offer the key
// an editor would complete; the descriptor's component still does.
func TestTheFragmentSchemaRefusesComponentControls(t *testing.T) {
	for path, offered := range map[string]bool{schemaPath: true, fragmentSchemaPath: false} {
		doc := readSchema(t, path)
		items, _ := doc["properties"].(map[string]any)["components"].(map[string]any)["items"].(map[string]any)
		ref, _ := items["$ref"].(string)
		def := definitionFor(t, doc, strings.TrimPrefix(ref, "#/$defs/"))
		props, _ := def["properties"].(map[string]any)
		if def["additionalProperties"] != false {
			t.Errorf("%s: %s accepts keys it does not list", path, ref)
		}
		for _, key := range []string{"controls", "controllers"} {
			if _, has := props[key]; has != offered {
				t.Errorf("%s: %s offers `%s` = %v, want %v", path, ref, key, has, offered)
			}
		}
	}
}
