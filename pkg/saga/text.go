package saga

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// UnquotedText is a value YAML reads as a number or a boolean, written unquoted where a field takes
// text, and where it is in the document.
type UnquotedText struct {
	// Path is the dotted key, with `[i]` for a list item, e.g. `config.publishers[0].dir`.
	Path string
	// Line is the line the value is on.
	Line int
	// Value is the value as written, such as `true`, `1.0` or `2024`.
	Value string
	// ReadAs is what YAML reads it as: "a boolean" or "a number".
	ReadAs string
}

// String is the warning a reader is shown: the field, the line, and the quoted value to copy.
func (u UnquotedText) String() string {
	return fmt.Sprintf("%s: %s on line %d is read as %s, and this field takes text. Write it in "+
		"quotes, %q; a later release refuses it unquoted.", u.Path, u.Value, u.Line, u.ReadAs, u.Value)
}

var (
	unmarshalerType = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()
	textType        = reflect.TypeOf("")
)

// readAs names what YAML reads a plain scalar as, for the tags that are not text.
var readAs = map[string]string{
	"!!bool":  "a boolean",
	"!!int":   "a number",
	"!!float": "a number",
}

// UnquotedTexts lists every field of a document decoding into a value of type into whose Go type
// is a string and whose value is written unquoted and read by YAML as a number or a boolean, in
// document order.
//
// The decoder keeps the text of any scalar in a string field, so `dir: true` loads as a directory
// named `true` and `version: 1.10` as the version "1.10", while an editor holding the file to the
// JSON Schema sees a boolean and a number. Quoting the value is what makes both readers see the
// text that was meant.
//
// The value of a map, such as a component's labels, is left alone. Its key is the author's own
// word, and `pci: true` says what it means.
func UnquotedTexts(root *yaml.Node, into reflect.Type) []UnquotedText {
	var found []UnquotedText
	var walk func(n *yaml.Node, t reflect.Type, path string)
	walk = func(n *yaml.Node, t reflect.Type, path string) {
		for n.Kind == yaml.AliasNode && n.Alias != nil {
			n = n.Alias
		}
		if n.Kind == yaml.DocumentNode {
			for _, c := range n.Content {
				walk(c, t, path)
			}
			return
		}
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if reflect.PointerTo(t).Implements(unmarshalerType) {
			return // the type decodes itself and says what it accepts
		}
		switch {
		case t.Kind() == reflect.String:
			// Plain style only: a quoted, block or explicitly tagged scalar is text as written.
			if as, ok := readAs[n.Tag]; ok && n.Kind == yaml.ScalarNode && n.Style == 0 {
				found = append(found, UnquotedText{Path: path, Line: n.Line, Value: n.Value, ReadAs: as})
			}
		case t.Kind() == reflect.Struct && n.Kind == yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				key := n.Content[i].Value
				if f, ok := fieldByKey(t, key); ok {
					walk(n.Content[i+1], f.Type, strings.TrimPrefix(path+"."+key, "."))
				}
			}
		case (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) && n.Kind == yaml.SequenceNode:
			for i, c := range n.Content {
				walk(c, t.Elem(), fmt.Sprintf("%s[%d]", path, i))
			}
		case t.Kind() == reflect.Map && n.Kind == yaml.MappingNode && t.Elem() != textType:
			for i := 0; i+1 < len(n.Content); i += 2 {
				walk(n.Content[i+1], t.Elem(), strings.TrimPrefix(path+"."+n.Content[i].Value, "."))
			}
		}
	}
	walk(root, into, "")
	return found
}

// fieldByKey finds the field of struct type t that the YAML key decodes into.
func fieldByKey(t reflect.Type, key string) (reflect.StructField, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("yaml"), ","); name == key && name != "-" {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

// textWarnings is UnquotedTexts as the warnings a run and `draugr validate` print, each prefixed
// with where, which names a fragment and is empty for the descriptor itself.
func textWarnings(root *yaml.Node, into reflect.Type, where string) []string {
	var out []string
	for _, u := range UnquotedTexts(root, into) {
		out = append(out, where+u.String())
	}
	return out
}
