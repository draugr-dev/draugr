package config

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Set writes key=value into a configuration document, returning the new bytes.
//
// The document is edited as a node tree rather than decoded and re-encoded, so **comments
// survive**. A `config set` that silently deleted the explanation somebody wrote next to a
// version pin would teach people not to use it, and they would go back to hand-editing the file
// this command exists to keep valid.
//
// The key is a dotted path, `tools.trivy.version`, `controls.sca.mend.policy`. Intermediate
// mappings are created as needed, in block style, and an empty `{}` on the way becomes one too.
//
// A value starting with `[` or `{` is a YAML flow list or mapping, `[library]` or `{config: x}`;
// anything else is one scalar, so a URL or a value holding `: ` is written as typed. The rule reads
// only the first character, because a value whose meaning depends on whether it happens to parse
// is a value nobody can predict.
func Set(doc []byte, key, value string) ([]byte, error) {
	path, err := splitKey(key)
	if err != nil {
		return nil, err
	}
	node, err := valueNode(value)
	if err != nil {
		return nil, err
	}
	root, err := parseDoc(doc)
	if err != nil {
		return nil, err
	}

	m := blockIfEmpty(root.Content[0])
	for _, seg := range path[:len(path)-1] {
		m = childMapping(m, seg)
	}
	setValue(m, path[len(path)-1], node)

	return render(root)
}

// NotSetError is Unset's answer for a key the document does not hold.
type NotSetError struct {
	// Key is the dotted key that was asked for.
	Key string
}

func (e *NotSetError) Error() string { return fmt.Sprintf("%q is not set", e.Key) }

// Unset removes a key, and any mapping it leaves empty. A key the document does not hold is a
// *NotSetError and no document, so the caller writes nothing.
//
// The cleanup matters: a `controls.sca.mend` left behind as an empty mapping after its last
// setting is removed is not the same file as one that never mentioned mend, and the difference
// shows up later as a scanner block that exists and configures nothing.
//
// A key under `controls` also finds the same key under the older `controllers`, and the other way
// round, because both spellings load as one section.
func Unset(doc []byte, key string) ([]byte, error) {
	path, err := splitKey(key)
	if err != nil {
		return nil, err
	}
	root, err := parseDoc(doc)
	if err != nil {
		return nil, err
	}
	if !removeTop(root.Content[0], path) {
		other := otherSpelling(path)
		if other == nil || !removeTop(root.Content[0], other) {
			return nil, &NotSetError{Key: key}
		}
	}
	return render(root)
}

// otherSpelling is path with its first segment swapped between `controls` and `controllers`, or
// nil when it starts with neither.
func otherSpelling(path []string) []string {
	var first string
	switch path[0] {
	case controlsKey:
		first = olderControlsKey
	case olderControlsKey:
		first = controlsKey
	default:
		return nil
	}
	return append([]string{first}, path[1:]...)
}

// valueNode is the node Set writes for value: a flow list or mapping when it starts with `[` or
// `{`, otherwise a scalar.
func valueNode(value string) (*yaml.Node, error) {
	if !strings.HasPrefix(value, "[") && !strings.HasPrefix(value, "{") {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: scalarTag(value), Value: value}, nil
	}
	want, kind := yaml.SequenceNode, "list"
	if value[0] == '{' {
		want, kind = yaml.MappingNode, "mapping"
	}
	// Parsed as the value of a one-key mapping, because a flow node parsed on its own ends where
	// the node does and drops anything after it: `[a] b` would be written as `[a]`.
	var doc yaml.Node
	err := yaml.Unmarshal([]byte("v: "+value), &doc)
	if err != nil || len(doc.Content) != 1 || len(doc.Content[0].Content) != 2 ||
		doc.Content[0].Content[1].Kind != want {
		return nil, fmt.Errorf("%q starts with %q, so it is read as a YAML %s and is not one; "+
			"write a %s as %s", value, value[:1], kind, kind, flowExample(kind))
	}
	n := doc.Content[0].Content[1]
	n.Style = yaml.FlowStyle
	return n, nil
}

// flowExample shows the shape a flow value of kind takes.
func flowExample(kind string) string {
	if kind == "list" {
		return "[a, b]"
	}
	return "{key: value}"
}

// blockIfEmpty turns an empty flow mapping, `{}`, into a block one, so the first key added to it
// is written on its own line rather than as `{key: value}` beside the comments around it. A flow
// mapping that already holds keys keeps the style somebody chose for it.
func blockIfEmpty(m *yaml.Node) *yaml.Node {
	if m.Kind == yaml.MappingNode && len(m.Content) == 0 {
		m.Style &^= yaml.FlowStyle
	}
	return m
}

// Get returns the value at a dotted key, and whether it was there.
func Get(doc []byte, key string) (string, bool) {
	path, err := splitKey(key)
	if err != nil {
		return "", false
	}
	root, err := parseDoc(doc)
	if err != nil || len(root.Content) == 0 {
		return "", false
	}
	n := root.Content[0]
	for _, seg := range path {
		if n = mappingValue(n, seg); n == nil {
			return "", false
		}
	}
	if n.Kind != yaml.ScalarNode {
		return "", false
	}
	return n.Value, true
}

// splitKey validates and splits a dotted path.
func splitKey(key string) ([]string, error) {
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("empty key: give a dotted path, e.g. tools.trivy.version")
	}
	parts := strings.Split(key, ".")
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("%q has an empty segment", key)
		}
	}
	return parts, nil
}

// parseDoc parses a document, treating an empty one as an empty mapping so a first `set` works
// against a file that does not exist yet.
func parseDoc(doc []byte) (*yaml.Node, error) {
	var root yaml.Node
	if len(bytes.TrimSpace(doc)) > 0 {
		if err := yaml.Unmarshal(doc, &root); err != nil {
			return nil, fmt.Errorf("the file is not valid YAML: %w", err)
		}
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		root = yaml.Node{
			Kind:    yaml.DocumentNode,
			Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}},
		}
	}
	return &root, nil
}

// render encodes the tree back, at the indentation the rest of Draugr's YAML uses.
func render(root *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// mappingValue returns the value node for key, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// childMapping returns the mapping at key, creating it if absent.
func childMapping(m *yaml.Node, key string) *yaml.Node {
	if v := mappingValue(m, key); v != nil && v.Kind == yaml.MappingNode {
		return blockIfEmpty(v)
	}
	child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = child // replace a scalar standing where a mapping is needed
			return child
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, child)
	return child
}

// setValue sets or replaces the value at key, leaving any comment on the key or its old value in
// place.
func setValue(m *yaml.Node, key string, n *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			old := m.Content[i+1]
			n.HeadComment, n.LineComment, n.FootComment = old.HeadComment, old.LineComment, old.FootComment
			m.Content[i+1] = n
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, n)
}

// scalarTag keeps a version like "0.69.3" a string while letting true/false and numbers be
// themselves. `enabled: "true"` is not the same setting as `enabled: true`, and a config file
// that quietly turns one into the other is worse than one that refuses to write.
func scalarTag(v string) string {
	switch strings.ToLower(v) {
	case "true", "false":
		return "!!bool"
	}
	// Integer before float: "30" round-trips through both, and %g would make it 30.0. A timeout
	// that reads differently from the one that was typed.
	if i, err := strconv.ParseInt(v, 10, 64); err == nil && strconv.FormatInt(i, 10) == v {
		return "!!int"
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil && strconv.FormatFloat(f, 'g', -1, 64) == v {
		return "!!float"
	}
	return "!!str"
}

// removeTop is removePath for the top of a document, where a section emptied by the removal stays
// as `{}` when a comment is attached to it. An empty top-level section configures nothing, and the
// comment is somebody's explanation of the file, which an edit never discards.
func removeTop(m *yaml.Node, path []string) bool {
	section := mappingValue(m, path[0])
	if len(path) == 1 || section == nil || !commented(m, path[0]) {
		return removePath(m, path)
	}
	if !removePath(section, path[1:]) {
		return false
	}
	if len(section.Content) == 0 {
		section.Style |= yaml.FlowStyle
	}
	return true
}

// commented reports whether the entry for key in m carries a comment, on its key or its value.
func commented(m *yaml.Node, key string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != key {
			continue
		}
		for _, n := range m.Content[i : i+2] {
			if n.HeadComment != "" || n.LineComment != "" || n.FootComment != "" {
				return true
			}
		}
	}
	return false
}

// removePath deletes the key at path and prunes mappings it empties.
func removePath(m *yaml.Node, path []string) bool {
	if m == nil || m.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != path[0] {
			continue
		}
		if len(path) == 1 {
			m.Content = append(m.Content[:i:i], m.Content[i+2:]...)
			return true
		}
		if !removePath(m.Content[i+1], path[1:]) {
			return false
		}
		if len(m.Content[i+1].Content) == 0 {
			m.Content = append(m.Content[:i:i], m.Content[i+2:]...)
		}
		return true
	}
	return false
}
