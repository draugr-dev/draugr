package schemagen

import (
	"encoding/json"
	"maps"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// tables returns copies of the two tables, for a test to break one entry of.
func tables() (map[string]map[string]any, map[string]map[string]any) {
	return maps.Clone(sagaFields()), maps.Clone(sagaDefinitions())
}

// The generator refuses to write a schema it cannot vouch for, and names what to fix. Each of these
// is what a change to pkg/saga or to the tables produces when its author forgets the other half.
func TestSagaSchemaRefusesWhatItCannotDescribe(t *testing.T) {
	for _, c := range []struct {
		name  string
		spoil func(fields, defs map[string]map[string]any)
		want  string
	}{
		{"a field with no entry", func(f, _ map[string]map[string]any) { delete(f, "publisherConfig.dir") },
			"publisherConfig.dir has no entry in sagaFields"},
		{"an entry for a field that is gone", func(f, _ map[string]map[string]any) { f["publisherConfig.directory"] = map[string]any{} },
			"publisherConfig.directory"},
		{"a field with no description", func(f, _ map[string]map[string]any) { f["publisherConfig.dir"] = map[string]any{} },
			"publisherConfig.dir has no description"},
		{"a definition with no entry", func(_, d map[string]map[string]any) { delete(d, "hostSpec") },
			"definition hostSpec has no entry"},
		{"an entry for a definition that is gone", func(_, d map[string]map[string]any) { d["hostSpecs"] = map[string]any{} },
			"$defs.hostSpecs"},
		{"a vocabulary missing a value the loader accepts", func(f, _ map[string]map[string]any) {
			f["host.type"] = map[string]any{"description": "d", "anyOf": vocab(saga.HostTypes, valueDoc{"browser", "b"})}
		}, "host.type: the schema would offer [browser] and the loader accepts [browser api]"},
		{"a vocabulary value with no description", func(f, _ map[string]map[string]any) {
			f["host.type"] = map[string]any{"description": "d", "anyOf": vocab(saga.HostTypes, valueDoc{"browser", " "}, valueDoc{"api", "a"})}
		}, `host.type: "browser" has no description`},
		{"a vocabulary inside a definition", func(_, d map[string]map[string]any) {
			d["exposure"] = map[string]any{"anyOf": vocab(saga.Exposures, valueDoc{"public", "p"})}
		}, "exposure: the schema would offer [public]"},
		{"a vocabulary inside a list", func(_, d map[string]map[string]any) {
			d["account"] = map[string]any{"allOf": []any{vocab(saga.ProviderValues)}}
		}, "account: the schema would offer []"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fields, defs := tables()
			c.spoil(fields, defs)
			_, err := sagaSchema(builtins.Registry(), fields, defs)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want one naming %q", err, c.want)
			}
		})
	}
}

// A type the generator has no shape for fails generation rather than being written as nothing.
func TestSagaShaperNamesATypeItCannotShape(t *testing.T) {
	s := &sagaShaper{out: map[string]any{}}
	if _, err := s.shape(reflect.TypeOf(complex64(0)), "x.y"); err == nil || !strings.Contains(err.Error(), "x.y") {
		t.Errorf("err = %v, want one naming the path", err)
	}
	type unnamed struct{ A string }
	if _, err := s.shape(reflect.TypeOf(unnamed{}), "x"); err == nil || !strings.Contains(err.Error(), "sagaDefNames") {
		t.Errorf("err = %v, want one naming sagaDefNames", err)
	}
	if _, err := s.shape(reflect.TypeOf([]complex64{}), "x"); err == nil {
		t.Error("a list of a type with no shape was shaped")
	}
	if _, err := s.shape(reflect.TypeOf(map[string]complex64{}), "x"); err == nil {
		t.Error("a map of a type with no shape was shaped")
	}
}

// A text field is typed as text, and a map value such as a label keeps any scalar: the line the
// loader draws with saga.UnquotedTexts, drawn in the same place.
func TestATextFieldTakesQuotedTextAndALabelAnyValue(t *testing.T) {
	doc := generated(t)
	defs := doc["$defs"].(map[string]any)
	prop := func(def, key string) map[string]any {
		return defs[def].(map[string]any)["properties"].(map[string]any)[key].(map[string]any)
	}
	for _, c := range []struct{ def, key string }{
		{"publisherConfig", "dir"}, {"release", "version"}, {"repository", "revision"}, {"account", "account"},
	} {
		if got := prop(c.def, c.key)["type"]; got != "string" {
			t.Errorf("%s.%s is typed %v, want string", c.def, c.key, got)
		}
	}
	if got := doc["properties"].(map[string]any)["project"].(map[string]any)["type"]; got != "string" {
		t.Errorf("project is typed %v, want string", got)
	}
	for _, c := range []struct{ def, key string }{
		{"component", "labels"}, {"publisherSelect", "labels"}, {"issueItem", "fields"},
	} {
		values, _ := json.Marshal(prop(c.def, c.key)["additionalProperties"].(map[string]any)["type"])
		if string(values) != `["string","number","boolean"]` {
			t.Errorf("%s.%s values are typed %s, want any scalar", c.def, c.key, values)
		}
	}
}
