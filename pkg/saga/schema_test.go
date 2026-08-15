package saga

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The JSON Schema is hand-authored so it can carry real descriptions and enums — editors show
// them as hover docs and completions, which a generated schema does poorly. The cost of hand
// authoring is drift, so this test walks the Go types and fails when a field isn't described.
// Add a field to the model, add it to the schema.
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

// yamlFields lists the yaml keys of a struct type.
func yamlFields(typ reflect.Type) []string {
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// schemaCase pairs a Go struct with the schema definition that describes it.
type schemaCase struct {
	def string
	typ any
}

// schemaCases is every Go struct a Saga can contain, and its definition.
//
// Hand-written, and TestEveryDescriptorStructIsGuarded is what keeps it honest: a struct reachable
// from a descriptor and absent here would have its fields checked by nothing.
func schemaCases() []schemaCase {
	return []schemaCase{
		{"", Model{}},
		{"release", Release{}},
		{"config", Config{}},
		{"reportConfig", ReportConfig{}},
		{"publisherConfig", PublisherConfig{}},
		{"component", Component{}},
		{"repository", Repository{}},
		{"image", Image{}},
		{"host", Host{}},
		{"hostAuth", HostAuth{}},
		{"infrastructure", Infrastructure{}},
		{"fragmentRef", FragmentRef{}},
		{"fragmentConfig", FragmentConfig{}},
		{"reference", Reference{}},
		{"excludeRule", ExcludeRule{}},
		{"gateConfig", GateConfig{}},
		{"sbomConfig", SBOMConfig{}},
		{"vexConfig", VEXConfig{}},
		{"vexDecision", VEXDecision{}},
		{"exploitabilityConfig", ExploitabilityConfig{}},
	}
}

func TestSchemaCoversEveryModelField(t *testing.T) {
	doc := loadSchema(t)

	for _, c := range schemaCases() {
		def := definitionFor(t, doc, c.def)
		props, ok := def["properties"].(map[string]any)
		if !ok {
			t.Errorf("%s: schema definition has no properties", c.def)
			continue
		}
		for _, field := range yamlFields(reflect.TypeOf(c.typ)) {
			if _, described := props[field]; !described {
				name := c.def
				if name == "" {
					name = "(root)"
				}
				t.Errorf("%s: field %q exists in the Go model but not in the schema — "+
					"add it to schema/draugr.saga.schema.json", name, field)
			}
		}
		// The reverse: a property the model no longer has would mislead an editor.
		known := map[string]bool{}
		for _, f := range yamlFields(reflect.TypeOf(c.typ)) {
			known[f] = true
		}
		for prop := range props {
			if !known[prop] {
				t.Errorf("%s: schema describes %q, which the Go model does not have", c.def, prop)
			}
		}
	}
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

// A schema that doesn't accept our own examples is worse than none.
func TestSchemaIdIsThePublishedURL(t *testing.T) {
	doc := loadSchema(t)
	const want = "https://draugr.dev/schema/draugr.saga.schema.json"
	if got, _ := doc["$id"].(string); got != want {
		t.Errorf("$id = %q, want %q — editors resolve $ref against it", got, want)
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
// disagree, an editor contradicts the CLI — which is worse than either being lenient alone. This
// asserts they reject the same things, for the cases people actually hit.
func TestLoaderRejectsWhatTheSchemaRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field at the root": `
release: {name: a, version: "1"}
bogus: true`,
		"unknown field in release": `
release: {name: a, version: "1", bogusField: x}`,
		"unknown field in a component": `
release: {name: a, version: "1"}
components:
  - name: web
    repositores: []`,
		"unknown field in a repository": `
release: {name: a, version: "1"}
components:
  - name: web
    repositories:
      - url: .
        branch: main`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			// additionalProperties:false in the schema — the loader must agree.
			if _, err := Load([]byte(doc)); err == nil {
				t.Error("the loader accepted a document the schema rejects")
			}
		})
	}
}

// …and conversely, that strictness must not reach into scanner options, which are deliberately
// open: each scanner validates its own block against its ConfigSchema when the scan is planned.
func TestScannerOptionsStayFreeForm(t *testing.T) {
	doc := `
release: {name: a, version: "1"}
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
	_, err := Load([]byte("release: {name: a, version: \"1\", bogusField: x}"))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{`"bogusField"`, "release"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

// descriptorStructs walks the model from the root, collecting every named struct a descriptor can
// contain — through pointers, slices and map values.
func descriptorStructs(t reflect.Type, seen map[reflect.Type]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() || f.Tag.Get("yaml") == "-" {
			continue
		}
		descriptorStructs(f.Type, seen)
	}
}

// inlinedInSchema are model structs the schema deliberately gives no definition of their own.
// Each needs a reason here, because "no definition" is also what an unguarded type looks like.
var inlinedInSchema = map[string]string{
	"Model":    "the root document, covered by the \"\" case",
	"Fragment": "described by the generated fragment schema, kept in step by internal/schemagen",
	"Resolved": "a load result, never written by a user",
	"Source":   "provenance of a loaded file, never written by a user",
}

// TestEveryDescriptorStructIsGuarded stops the coverage check from silently examining less than the
// model contains.
//
// schemaCases is written by hand, so a struct added to the descriptor is only checked if somebody
// remembers to add it there. Seven were missing when this was written — each correct, and none of
// them checked by anything. What that costs is felt in an editor first: a field Draugr accepts and
// the schema has never heard of is underlined as an error while it works perfectly.
func TestEveryDescriptorStructIsGuarded(t *testing.T) {
	t.Parallel()

	reachable := map[reflect.Type]bool{}
	descriptorStructs(reflect.TypeOf(Model{}), reachable)

	guarded := map[string]bool{}
	for _, c := range schemaCases() {
		guarded[reflect.TypeOf(c.typ).Name()] = true
	}

	for typ := range reachable {
		name := typ.Name()
		if guarded[name] || inlinedInSchema[name] != "" {
			continue
		}
		t.Errorf("%s is reachable from a descriptor, and no schemaCases entry covers it. Add "+
			"{\"<definition>\", %s{}} there, or record in inlinedInSchema why it has no "+
			"definition of its own", name, name)
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

	// The two maps are keyed by control and by scanner name, so their additionalProperties
	// describes the values rather than forbidding them. Strictness for those lives in the value
	// schema, and in the validator that rejects a control or scanner this build does not have.
	openByDesign := map[string]string{
		"controllers":        "a map keyed by control name",
		"controllerSettings": "a map keyed by scanner name",
	}

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
			t.Errorf("$defs.%s accepts unknown keys — add \"additionalProperties\": false so a "+
				"mistyped key is reported rather than silently accepted", name)
		}
	}
}
