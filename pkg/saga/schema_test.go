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
const schemaPath = "../../schema/draugr.saga.schema.json"

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(schemaPath))
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

func TestSchemaCoversEveryModelField(t *testing.T) {
	doc := loadSchema(t)

	// Each Go struct that appears in a Saga, and the schema definition describing it.
	cases := []struct {
		def string
		typ any
	}{
		{"", Model{}},
		{"release", Release{}},
		{"config", Config{}},
		{"reportConfig", ReportConfig{}},
		{"publisherConfig", PublisherConfig{}},
		{"component", Component{}},
		{"repository", Repository{}},
		{"image", Image{}},
		{"host", Host{}},
		{"infrastructure", Infrastructure{}},
		{"metaSource", MetaSource{}},
		{"reference", Reference{}},
	}

	for _, c := range cases {
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
