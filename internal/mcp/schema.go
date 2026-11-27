package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// --- get_saga_schema ---

// The whole Saga schema runs past a hundred thousand characters, more than an agent's client will
// put in front of the model in one tool result. Claude Code, for one, saves a result over 50,000
// characters to a file and hands the model the path instead. So the tool answers one field at a
// time, and without a field gives an outline of every field to choose from.

// maxSchemaResult is the most a get_saga_schema result may hold, in characters of its JSON.
// It sits well under the 50,000 above, with room for the schema to grow. A test walks every field
// and holds each answer to it.
const maxSchemaResult = 24_000

// SchemaInput names the field to describe.
type SchemaInput struct {
	Field string `json:"field,omitempty" jsonschema:"a dotted path to one field, such as components.exposure or config.gate, running through lists and maps without an index; leave it out for an outline of every field"`
}

// SchemaField is one line of the outline: a field, what it holds, and the values it takes.
type SchemaField struct {
	Path        string   `json:"path" jsonschema:"the field's dotted path, which can be passed back as field"`
	Type        string   `json:"type,omitempty"`
	Description string   `json:"description,omitempty"`
	Values      []string `json:"values,omitempty" jsonschema:"the only values the field accepts, where it has a fixed set"`
}

// SchemaOutput carries the definition of one field of the descriptor, or the outline of them all.
//
// Schema is a decoded object rather than raw bytes so a client receives the schema itself: MCP
// validates a tool's output against the schema derived from this type, and a []byte field
// derives as an array, which the schema document then fails to be.
type SchemaOutput struct {
	Field   string         `json:"field,omitempty" jsonschema:"the field this answer describes; empty for the outline"`
	Schema  map[string]any `json:"schema,omitempty" jsonschema:"the field's JSON Schema; an object defined elsewhere appears as a $comment naming the field to ask for"`
	Fields  []SchemaField  `json:"fields,omitempty" jsonschema:"one line per field directly under the field asked for; with no field, one line per top-level field and per field under it"`
	Version string         `json:"draugrVersion" jsonschema:"the Draugr build this schema came from"`
	Hint    string         `json:"hint"`
}

// GetSchema describes one field of the schema embedded in this binary, the one that will actually
// be enforced, as opposed to whatever is published on the web for some other version. An empty
// field gives the outline.
func GetSchema(field string) (SchemaOutput, error) {
	var root map[string]any
	if err := json.Unmarshal(saga.SchemaJSON, &root); err != nil {
		return SchemaOutput{}, fmt.Errorf("decode embedded schema: %w", err)
	}
	s := schemaDoc{root: root}
	if defs, ok := root["$defs"].(map[string]any); ok {
		s.defs = defs
	}
	const rejects = "Unknown keys are rejected, so field names must match exactly. " +
		"Validate any descriptor you write with validate_saga before relying on it."

	path := normalizeField(field)
	if path == "" {
		return SchemaOutput{
			Fields:  s.outline(),
			Version: version.Version,
			Hint: "Any path listed can be passed as field for its full definition and rules, and " +
				"each answer lists the fields under it. " + rejects,
		}, nil
	}
	node, err := s.lookup(path)
	if err != nil {
		return SchemaOutput{}, err
	}
	schema := s.expand(node, path)
	hint := rejects
	if raw, _ := json.Marshal(schema); strings.Contains(string(raw), askFor) {
		hint = "Where a part reads \"$comment\": \"ask for field <path>\", pass that path as " +
			"field to read it. " + rejects
	}
	return SchemaOutput{
		Field:   path,
		Schema:  schema,
		Fields:  s.children(node, path),
		Version: version.Version,
		Hint:    hint,
	}, nil
}

// askFor begins the $comment that stands in for an object defined elsewhere.
const askFor = "ask for field "

// schemaDoc is the decoded schema with its shared definitions to hand.
type schemaDoc struct {
	root map[string]any
	defs map[string]any
}

// index matches what a model may write for a position in a list, components[0] or components[].
var index = regexp.MustCompile(`\[[0-9]*\]`)

// normalizeField reads the forms a model is likely to write for one path, a list index or a
// leading dot included, as the plain dotted path the schema is walked by.
func normalizeField(field string) string {
	field = index.ReplaceAllString(strings.TrimSpace(field), "")
	var parts []string
	for _, p := range strings.Split(field, ".") {
		if p == "" || p == "$" || strings.Trim(p, "0123456789") == "" {
			continue
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ".")
}

// defName is the definition a $ref points at, or "" when the node is not a reference to one.
func defName(node map[string]any) string {
	ref, _ := node["$ref"].(string)
	return strings.TrimPrefix(ref, "#/$defs/")
}

// resolve follows a node's $ref to the definition, keeping what the node itself says on top of
// it: a property's own description of a shared definition is the more specific one.
func (s schemaDoc) resolve(node map[string]any) map[string]any {
	for range 16 {
		name := defName(node)
		if name == "" {
			return node
		}
		def, ok := s.defs[name].(map[string]any)
		if !ok {
			return node
		}
		merged := make(map[string]any, len(def)+len(node))
		for k, v := range def {
			merged[k] = v
		}
		for k, v := range node {
			if k != "$ref" {
				merged[k] = v
			}
		}
		node = merged
	}
	return node
}

// holds is what a list holds, or what a map that names no fields of its own holds under each key:
// the account under accounts, whatever it is called. Nil for anything else.
func holds(node map[string]any) map[string]any {
	if items, ok := node["items"].(map[string]any); ok {
		return items
	}
	if extra, ok := node["additionalProperties"].(map[string]any); ok && node["properties"] == nil {
		return extra
	}
	return nil
}

// element is what a node holds once lists and maps are looked through: a component, not the list
// of them.
func (s schemaDoc) element(node map[string]any) map[string]any {
	node = s.resolve(node)
	for range 8 {
		inner := holds(node)
		if inner == nil {
			return node
		}
		node = s.resolve(inner)
	}
	return node
}

// properties are the fields a node names, looking through a list or a map to what it holds.
func (s schemaDoc) properties(node map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	props, _ := s.element(node)["properties"].(map[string]any)
	for name, v := range props {
		if m, ok := v.(map[string]any); ok {
			out[name] = m
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// lookup walks a dotted path from the top of the descriptor. Lists and maps are looked through,
// so components.exposure is the exposure of each component and accounts.provider the provider of
// each account.
func (s schemaDoc) lookup(path string) (map[string]any, error) {
	node := s.root
	walked := ""
	for _, part := range strings.Split(path, ".") {
		props := s.properties(node)
		if next, ok := props[part]; ok {
			node = next
		} else {
			if len(props) == 0 {
				return nil, fmt.Errorf("%s is a single value with no fields under it, so %q "+
					"cannot be asked for. Ask for %s itself", walked, path, walked)
			}
			where := "The descriptor"
			if walked != "" {
				where = walked
			}
			return nil, fmt.Errorf("%s has no field %q. Its fields are: %s. Call get_saga_schema "+
				"with no field for the outline", where, part, strings.Join(sortedKeys(props), ", "))
		}
		walked = strings.TrimPrefix(walked+"."+part, ".")
	}
	return node, nil
}

// expand writes out a field's schema with every reference resolved. A shared definition of a value,
// such as exposure's four, is written in place, because the values belong in the answer about a
// component. A shared definition of an object with fields of its own becomes a pointer to the path
// that describes it, so one answer stays short and every part of the schema stays reachable.
func (s schemaDoc) expand(node map[string]any, path string) map[string]any {
	seen := map[string]bool{}
	out, _ := s.walk(s.top(node, seen), path, seen).(map[string]any)
	return out
}

// top resolves the field asked for, and what a list or a map of it holds: the answer about
// components is the component's definition, never a pointer back to components.
func (s schemaDoc) top(node map[string]any, seen map[string]bool) map[string]any {
	if name := defName(node); name != "" {
		seen[name] = true
	}
	node = s.resolve(node)
	inner := holds(node)
	if inner == nil {
		return node
	}
	out := make(map[string]any, len(node))
	for k, v := range node {
		out[k] = v
	}
	if _, ok := node["items"].(map[string]any); ok {
		out["items"] = s.top(inner, seen)
	} else {
		out["additionalProperties"] = s.top(inner, seen)
	}
	return out
}

func (s schemaDoc) walk(v any, path string, seen map[string]bool) any {
	switch v := v.(type) {
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = s.walk(e, path, seen)
		}
		return out
	case map[string]any:
		if name := defName(v); name != "" {
			full := s.resolve(v)
			if def, _ := s.defs[name].(map[string]any); def["properties"] == nil && !seen[name] {
				seen[name] = true
				out := s.walk(full, path, seen)
				delete(seen, name)
				return out
			}
			stub := map[string]any{"$comment": askFor + path}
			for _, k := range []string{"type", "description"} {
				if x, ok := full[k]; ok {
					stub[k] = x
				}
			}
			return stub
		}
		out := make(map[string]any, len(v))
		for k, e := range v {
			props, isProps := e.(map[string]any)
			if k != "properties" || !isProps {
				out[k] = s.walk(e, path, seen)
				continue
			}
			named := make(map[string]any, len(props))
			for name, p := range props {
				named[name] = s.walk(p, path+"."+name, seen)
			}
			out[k] = named
		}
		return out
	}
	return v
}

// outline is every top-level field and the fields under each, a line apiece.
func (s schemaDoc) outline() []SchemaField {
	var out []SchemaField
	props := s.properties(s.root)
	for _, name := range sortedKeys(props) {
		out = append(out, s.line(props[name], name))
		out = append(out, s.children(props[name], name)...)
	}
	return out
}

// children is a line for each field directly under a node.
func (s schemaDoc) children(node map[string]any, path string) []SchemaField {
	props := s.properties(node)
	out := make([]SchemaField, 0, len(props))
	for _, name := range sortedKeys(props) {
		out = append(out, s.line(props[name], path+"."+name))
	}
	return out
}

func (s schemaDoc) line(node map[string]any, path string) SchemaField {
	full := s.resolve(node)
	desc, _ := full["description"].(string)
	return SchemaField{
		Path:        path,
		Type:        s.typeOf(full),
		Description: firstSentence(desc),
		Values:      s.values(s.element(full)),
	}
}

// typeOf names what a field holds in a few words: "string", "list of object".
func (s schemaDoc) typeOf(node map[string]any) string {
	node = s.resolve(node)
	if items, ok := node["items"].(map[string]any); ok {
		return "list of " + s.typeOf(items)
	}
	switch t := node["type"].(type) {
	case string:
		if extra, ok := node["additionalProperties"].(map[string]any); ok && t == "object" && node["properties"] == nil {
			return "map of " + s.typeOf(extra)
		}
		return t
	case []any:
		var names []string
		for _, n := range t {
			if str, ok := n.(string); ok {
				names = append(names, str)
			}
		}
		return strings.Join(names, " or ")
	}
	return ""
}

// values are the fixed set a field accepts, from an enum or from alternatives that are each a
// constant, and none when any alternative is open.
func (s schemaDoc) values(node map[string]any) []string {
	var out []string
	if enum, ok := node["enum"].([]any); ok {
		for _, e := range enum {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		alts, ok := node[key].([]any)
		if !ok {
			continue
		}
		for _, a := range alts {
			m, _ := a.(map[string]any)
			c, ok := m["const"]
			if !ok {
				return nil
			}
			out = append(out, fmt.Sprint(c))
		}
	}
	return slices.Compact(out)
}

// sentenceEnd is a full stop followed by the start of another sentence, which "e.g. team" is not.
var sentenceEnd = regexp.MustCompile("[.!?]\\s+[A-Z`(]")

// firstSentence keeps an outline line to one line: the full description is in the field's answer.
func firstSentence(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if loc := sentenceEnd.FindStringIndex(s); loc != nil {
		return s[:loc[0]+1]
	}
	return s
}
