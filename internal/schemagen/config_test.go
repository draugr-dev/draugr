package schemagen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// configSchemaPath is the checked-in config schema the binary embeds.
func configSchemaPath() string {
	return filepath.Join(filepath.Dir(schemaPath()), "draugr.config.schema.json")
}

// regeneratedConfig is the config schema the generator would write from the checked-in Saga schema.
func regeneratedConfig(t *testing.T) []byte {
	t.Helper()
	current, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	sagaJSON, err := Apply(current, builtins.Registry())
	if err != nil {
		t.Fatal(err)
	}
	out, err := ConfigSchema(sagaJSON)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func loadConfigSchema(t *testing.T) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(saga.ConfigSchemaJSON, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// The config schema shares the Saga's control definitions, so it is right only while it is
// regenerated with them. Drift here is an editor and `draugr config validate` disagreeing about a
// scanner option.
func TestCheckedInConfigSchemaIsUpToDate(t *testing.T) {
	got, err := os.ReadFile(configSchemaPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(regeneratedConfig(t)) {
		t.Error("the checked-in config schema is not what the generator would produce, " +
			"run `go generate ./pkg/saga/...`")
	}
}

func TestEmbeddedConfigSchemaMatchesTheFileOnDisk(t *testing.T) {
	data, err := os.ReadFile(configSchemaPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(saga.ConfigSchemaJSON) != string(data) {
		t.Error("the embedded config schema differs from the checked-in file, so `draugr schema --config-file` " +
			"would hand out something the binary does not enforce")
	}
}

// TestTheConfigSchemaUsesTheSagaControls holds `controls` in both files to one definition per
// control, so a scanner option is the same option wherever it is written.
func TestTheConfigSchemaUsesTheSagaControls(t *testing.T) {
	cfg := loadConfigSchema(t)
	sagaDefs := loadSchema(t)["$defs"].(map[string]any)
	defs := cfg["$defs"].(map[string]any)
	for name, def := range sagaDefs {
		if !strings.HasPrefix(name, "control_") && name != "controllers" {
			continue
		}
		if !reflect.DeepEqual(defs[name], def) {
			t.Errorf("$defs.%s differs from the Saga schema's", name)
		}
	}
	props := cfg["properties"].(map[string]any)
	for _, key := range []string{"controls", "controllers"} {
		p, _ := props[key].(map[string]any)
		if p["$ref"] != "#/$defs/controllers" {
			t.Errorf("%s = %v, want a reference to the Saga's controllers definition", key, p)
		}
	}
	older, _ := props["controllers"].(map[string]any)
	if d, _ := older["description"].(string); !strings.HasPrefix(d, "Deprecated: write `controls`") {
		t.Errorf("controllers is not marked deprecated the way the Saga schema marks it: %q", d)
	}
	if cfg["$id"] != saga.ConfigSchemaURL {
		t.Errorf("$id = %v, want %s, which editors resolve $ref against", cfg["$id"], saga.ConfigSchemaURL)
	}
}

// TestTheConfigSchemaOffersWhatValidateAccepts checks the two vocabularies the file has beside the
// controls: the tools `tools install` provisions, and the report views.
func TestTheConfigSchemaOffersWhatValidateAccepts(t *testing.T) {
	cfg := loadConfigSchema(t)
	props := cfg["properties"].(map[string]any)
	toolProps := props["tools"].(map[string]any)["properties"].(map[string]any)
	var offered []string
	for name := range toolProps {
		offered = append(offered, name)
	}
	sort.Strings(offered)
	want := tools.Installable()
	sort.Strings(want)
	if !slices.Equal(offered, want) {
		t.Errorf("tools offers %v, `tools install` provisions %v", offered, want)
	}

	view := props["output"].(map[string]any)["properties"].(map[string]any)["view"].(map[string]any)
	var views []string
	for _, v := range view["anyOf"].([]any) {
		views = append(views, v.(map[string]any)["const"].(string))
	}
	var known []string
	for _, v := range report.Views() {
		known = append(known, string(v))
	}
	if !slices.Equal(views, known) {
		t.Errorf("output.view offers %v, a scan accepts %v", views, known)
	}
}

// TestTheConfigSchemaIsHeldToTheSameRule: every string closed or excused, and every object
// closed or excused, by the lists the Saga schema answers to plus the config file's own.
func TestTheConfigSchemaIsHeldToTheSameRule(t *testing.T) {
	seen := map[string]bool{}
	walkSchema(loadConfigSchema(t), "", func(path string, n map[string]any) {
		if isString(n) && !closed(n) {
			seen[path] = true
			_, ref := n["$ref"]
			_, inSaga := openStrings[path]
			_, own := configOpenStrings[path]
			if !ref && !inSaga && !own {
				t.Errorf("config schema: %s accepts any string. Close it, or add it to configOpenStrings "+
					"with the reason it cannot be closed.", path)
			}
		}
		if isObject(n) && !narrows(path) {
			if ap, ok := n["additionalProperties"].(bool); ok && !ap {
				return
			}
			if _, typed := n["additionalProperties"].(map[string]any); typed {
				return
			}
			if _, known := openObjects[path]; !known {
				t.Errorf("config schema: %s accepts keys Draugr does not read", path)
			}
		}
	})
	for path, why := range configOpenStrings {
		if !seen[path] {
			t.Errorf("configOpenStrings has %q (%s) and the config schema has no such open string; drop it", path, why)
		}
	}
}

// configOpenStrings are the config file's own free-form strings, each with why.
var configOpenStrings = map[string]string{
	"$defs.toolSettings.properties.version": "a release of the tool, numbered by its own project",
	"properties.cache.properties.dir":       "a directory on the machine running the scan",
	"properties.publish.properties.apiUrl":  "a server's URL, held to its allowed origins when a scan publishes rather than to a pattern",
}

// TestConfigSchemaRefusesWhatItCannotFillIn: the generator fails rather than writing a schema with
// a part missing, the same rule Apply follows.
func TestConfigSchemaRefusesWhatItCannotFillIn(t *testing.T) {
	current, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"not JSON":              []byte("not json"),
		"no $defs":              []byte(`{"type": "object"}`),
		"no controllers":        []byte(`{"$defs": {}}`),
		"a reference to a hole": []byte(`{"$defs": {"controllers": {"properties": {"sast": {"$ref": "#/$defs/control_sast"}}}}}`),
	}
	for name, in := range cases {
		if _, err := ConfigSchema(in); err == nil {
			t.Errorf("%s: ConfigSchema succeeded", name)
		}
	}

	missing := configFields()
	delete(missing, "output.top")
	if _, err := configSchema(current, missing); err == nil || !strings.Contains(err.Error(), "output.top") {
		t.Errorf("a field with no description: err = %v, want one naming output.top", err)
	}
	stale := configFields()
	stale["output.palette"] = map[string]any{"description": "x"}
	if _, err := configSchema(current, stale); err == nil || !strings.Contains(err.Error(), "output.palette") {
		t.Errorf("a description for no field: err = %v, want one naming output.palette", err)
	}
	s := &configShaper{docs: configFields(), defs: map[string]any{}, used: map[string]bool{}}
	if _, err := s.shape(reflect.TypeOf(map[string]float64{}), "output.ratio"); err == nil {
		t.Error("shape accepted a type it has no JSON Schema for")
	}
}
