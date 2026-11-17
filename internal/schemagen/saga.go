package schemagen

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// SagaSchemaComment is the Saga schema's one-line note to whoever opens the file.
const SagaSchemaComment = "Generated in full from pkg/saga and the plugin registry; before editing it by hand, " +
	"read docs/contributing/schema.md in the draugr repository."

// sagaDefNames names the definition each struct a descriptor can hold is written under. A struct
// reachable from a descriptor and missing here fails generation, so a type added to the model is
// described or the build says why not.
var sagaDefNames = map[reflect.Type]string{
	reflect.TypeOf(saga.Release{}):                "release",
	reflect.TypeOf(saga.Config{}):                 "config",
	reflect.TypeOf(saga.GateConfig{}):             "gateConfig",
	reflect.TypeOf(saga.ExcludeRule{}):            "excludeRule",
	reflect.TypeOf(saga.VEXDecision{}):            "vexDecision",
	reflect.TypeOf(saga.VEXConfig{}):              "vexConfig",
	reflect.TypeOf(saga.VEXSource{}):              "vexSource",
	reflect.TypeOf(saga.VEXRepository{}):          "vexRepository",
	reflect.TypeOf(saga.SBOMConfig{}):             "sbomConfig",
	reflect.TypeOf(saga.ExploitabilityConfig{}):   "exploitabilityConfig",
	reflect.TypeOf(saga.ReachabilityConfig{}):     "reachabilityConfig",
	reflect.TypeOf(saga.DependencyHealthConfig{}): "dependencyHealthConfig",
	reflect.TypeOf(saga.CIConfig{}):               "ciConfig",
	reflect.TypeOf(saga.FixesConfig{}):            "fixesConfig",
	reflect.TypeOf(saga.ReportConfig{}):           "reportConfig",
	reflect.TypeOf(saga.PublisherConfig{}):        "publisherConfig",
	reflect.TypeOf(saga.PublisherSelect{}):        "publisherSelect",
	reflect.TypeOf(saga.IssueItem{}):              "issueItem",
	reflect.TypeOf(saga.Component{}):              "component",
	reflect.TypeOf(saga.Import{}):                 "import",
	reflect.TypeOf(saga.ImportSeverity{}):         "importSeverity",
	reflect.TypeOf(saga.Repository{}):             "repository",
	reflect.TypeOf(saga.Image{}):                  "image",
	reflect.TypeOf(saga.Host{}):                   "host",
	reflect.TypeOf(saga.HostAuth{}):               "hostAuth",
	reflect.TypeOf(saga.HostSpec{}):               "hostSpec",
	reflect.TypeOf(saga.Cluster{}):                "cluster",
	reflect.TypeOf(saga.ClusterRef{}):             "clusterRef",
	reflect.TypeOf(saga.Account{}):                "account",
	reflect.TypeOf(saga.AccountRef{}):             "accountRef",
	reflect.TypeOf(saga.FragmentRef{}):            "fragmentRef",
	reflect.TypeOf(saga.Reference{}):              "reference",
	reflect.TypeOf(saga.FragmentConfig{}):         "fragmentConfig",
}

var (
	exposureType     = reflect.TypeOf(saga.Exposure(""))
	criticalityType  = reflect.TypeOf(saga.Criticality(""))
	effectsType      = reflect.TypeOf(saga.EffectPermissions{})
	sagaControlsType = reflect.TypeOf(map[string]saga.ControllerSettings{})
)

// valueDoc is one value of a closed vocabulary and what an editor shows beside it.
type valueDoc struct{ value, description string }

// vocab is a closed vocabulary as the schema writes one: an `anyOf` of `const`, each with its
// description, in the order docs gives them. values is the Go list the loader checks against, and
// a value in one list and not the other fails generation, so the schema cannot offer a value
// Draugr refuses or miss one it accepts.
func vocab[T ~string](values []T, docs ...valueDoc) vocabulary {
	want := make([]string, len(values))
	for i, v := range values {
		want[i] = string(v)
	}
	return vocabulary{want: want, docs: docs}
}

// vocabulary is a vocab before it is checked and written.
type vocabulary struct {
	want []string
	docs []valueDoc
}

// anyOf checks the vocabulary against its Go list and writes it.
func (v vocabulary) anyOf(at string) ([]any, error) {
	got := make([]string, len(v.docs))
	out := make([]any, len(v.docs))
	for i, d := range v.docs {
		if strings.TrimSpace(d.description) == "" {
			return nil, fmt.Errorf("%s: %q has no description", at, d.value)
		}
		got[i] = d.value
		out[i] = map[string]any{"const": d.value, "description": d.description}
	}
	a, b := slices.Clone(got), slices.Clone(v.want)
	sort.Strings(a)
	sort.Strings(b)
	if !slices.Equal(a, b) {
		return nil, fmt.Errorf("%s: the schema would offer %v and the loader accepts %v", at, got, v.want)
	}
	return out, nil
}

// anyText is the shape of a map value that keeps whatever is written, such as a component's label.
// The key is the author's own word, so `pci: true` says what it means, and the loader keeps the
// text of a number or a boolean there.
func anyText() map[string]any { return map[string]any{"type": []any{"string", "number", "boolean"}} }

// sagaShaper builds the Saga schema's definitions from pkg/saga's types, one field at a time.
type sagaShaper struct {
	fields map[string]map[string]any
	defs   map[string]map[string]any
	out    map[string]any
	used   map[string]bool
}

// resolve turns every vocabulary in an overlay into the `anyOf` it stands for.
func resolve(v any, at string) (any, error) {
	switch x := v.(type) {
	case vocabulary:
		return x.anyOf(at)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, c := range x {
			r, err := resolve(c, at)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, c := range x {
			r, err := resolve(c, at)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	}
	return v, nil
}

// overlay lays the table's entry over the shape read from the Go type. A `$ref` in the entry
// replaces the shape, since a reference stands for the whole node.
func overlay(node, over map[string]any) map[string]any {
	if _, ref := over["$ref"]; ref {
		return over
	}
	for k, v := range over {
		sub, isMap := v.(map[string]any)
		existing, both := node[k].(map[string]any)
		if isMap && both {
			node[k] = overlay(existing, sub)
			continue
		}
		node[k] = v
	}
	return node
}

// shape is the schema for a value of type t, at the dotted path a reader writes.
func (s *sagaShaper) shape(t reflect.Type, at string) (map[string]any, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == exposureType:
		return map[string]any{"$ref": "#/$defs/exposure"}, nil
	case t == criticalityType:
		return map[string]any{"$ref": "#/$defs/criticality"}, nil
	case t == sagaControlsType:
		return map[string]any{"$ref": "#/$defs/controllers"}, nil
	case t == effectsType:
		// Written by allowEffectsDef from the effect taxonomy.
		return map[string]any{}, nil
	case t.Kind() == reflect.Struct:
		name, err := s.define(t)
		if err != nil {
			return nil, err
		}
		return map[string]any{"$ref": "#/$defs/" + name}, nil
	case t.Kind() == reflect.Slice:
		items, err := s.shape(t.Elem(), at+"[]")
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "array", "items": items}, nil
	case t.Kind() == reflect.Map && t.Key().Kind() == reflect.String:
		if t.Elem().Kind() == reflect.String {
			return map[string]any{"type": "object", "additionalProperties": anyText()}, nil
		}
		values, err := s.shape(t.Elem(), at+".*")
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "object", "additionalProperties": values}, nil
	case t.Kind() == reflect.String:
		// Text, quoted. YAML reads an unquoted `true` as a boolean and `1.20` as a number, and the
		// loader warns about either in a field that takes text (saga.UnquotedText), so the schema
		// offers only the quoted form.
		return map[string]any{"type": "string"}, nil
	case t.Kind() == reflect.Bool:
		return map[string]any{"type": "boolean"}, nil
	case t.Kind() == reflect.Int:
		return map[string]any{"type": "integer"}, nil
	case t.Kind() == reflect.Float64:
		return map[string]any{"type": "number"}, nil
	}
	return nil, fmt.Errorf("%s: no JSON Schema shape for a %s; teach sagaShaper.shape the type", at, t)
}

// properties shapes every field of struct type t, keyed as the descriptor writes it, with each
// field's entry in sagaFields laid over it. owner is the definition's name, "" for the root.
func (s *sagaShaper) properties(t reflect.Type, owner string) (map[string]any, error) {
	props := map[string]any{}
	for i := range t.NumField() {
		f := t.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if key == "" || key == "-" || !f.IsExported() {
			continue
		}
		path := key
		if owner != "" {
			path = owner + "." + key
		}
		node, err := s.shape(f.Type, path)
		if err != nil {
			return nil, err
		}
		doc, ok := s.fields[path]
		if !ok {
			return nil, fmt.Errorf("%s has no entry in sagaFields, so the schema cannot say what it does", path)
		}
		s.used[path] = true
		over, err := resolve(doc, path)
		if err != nil {
			return nil, err
		}
		node = overlay(node, over.(map[string]any))
		_, ref := node["$ref"]
		if d, _ := node["description"].(string); strings.TrimSpace(d) == "" && !ref {
			return nil, fmt.Errorf("%s has no description in sagaFields; a field that is not a "+
				"reference to a definition says what it does", path)
		}
		props[key] = node
	}
	return props, nil
}

// define writes the definition of struct type t, once, and returns its name.
func (s *sagaShaper) define(t reflect.Type) (string, error) {
	name, ok := sagaDefNames[t]
	if !ok {
		return "", fmt.Errorf("%s is reachable from a descriptor and has no name in sagaDefNames", t)
	}
	if _, done := s.out[name]; done {
		return name, nil
	}
	def := map[string]any{"type": "object", "additionalProperties": false}
	s.out[name] = def // placed first, so a type that refers to itself ends
	props, err := s.properties(t, name)
	if err != nil {
		return "", err
	}
	def["properties"] = props
	if err := s.lay(name, def); err != nil {
		return "", err
	}
	return name, nil
}

// lay writes the definition-level entry for name over def.
func (s *sagaShaper) lay(name string, def map[string]any) error {
	doc, ok := s.defs[name]
	if !ok {
		return fmt.Errorf("definition %s has no entry in sagaDefinitions", name)
	}
	s.used["$defs."+name] = true
	over, err := resolve(doc, name)
	if err != nil {
		return err
	}
	overlay(def, over.(map[string]any))
	return nil
}

// SagaSchema generates the Saga's JSON Schema: the descriptor's shape from pkg/saga's types and the
// descriptions in sagaFields and sagaDefinitions, then the parts the plugin registry answers for.
//
// Generated in full rather than half written by hand, because a hand-written half drifts from the
// loader in ways no check catches: every text field was typed as a string, a number or a boolean,
// so an editor offered `dir: true`, and the run wrote its reports into a directory named `true`.
func SagaSchema(reg *engine.Registry) ([]byte, error) {
	return sagaSchema(reg, sagaFields(), sagaDefinitions())
}

// sagaSchema is SagaSchema with the tables passed in.
func sagaSchema(reg *engine.Registry, fields, defs map[string]map[string]any) ([]byte, error) {
	s := &sagaShaper{fields: fields, defs: defs, out: map[string]any{}, used: map[string]bool{}}
	props, err := s.properties(reflect.TypeOf(saga.Model{}), "")
	if err != nil {
		return nil, err
	}
	// The fragment's config is not reachable from a descriptor, and the fragment schema is derived
	// from this one, so its definition lives here.
	if _, err := s.define(reflect.TypeOf(saga.FragmentConfig{})); err != nil {
		return nil, err
	}
	// The definitions a reference names rather than a struct: the two classification ladders and
	// the controls block, whose properties the registry writes.
	for _, name := range []string{"exposure", "criticality", "controllers"} {
		def := map[string]any{}
		if err := s.lay(name, def); err != nil {
			return nil, err
		}
		s.out[name] = def
	}
	var stale []string
	for path := range fields {
		if !s.used[path] {
			stale = append(stale, path)
		}
	}
	for name := range defs {
		if !s.used["$defs."+name] {
			stale = append(stale, "$defs."+name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		return nil, fmt.Errorf("the tables describe %s, which pkg/saga does not have", strings.Join(stale, ", "))
	}

	doc := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"$id":                  saga.SchemaURL,
		"$comment":             SagaSchemaComment,
		"title":                "Draugr Saga",
		"description":          sagaDescription,
		"type":                 "object",
		"additionalProperties": false,
		"properties":           props,
		"$defs":                s.out,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return Apply(raw, reg)
}

// sagaDescription is what an editor shows for the whole file.
const sagaDescription = "The draugr.saga.yaml descriptor, a declarative account of an application's " +
	"security surface and the controls that must pass. See https://draugr.dev/docs/latest/reference/saga-schema/"
