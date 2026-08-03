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
// The key is a dotted path — `tools.trivy.version`, `controllers.sca.mend.policy`. Intermediate
// mappings are created as needed.
func Set(doc []byte, key, value string) ([]byte, error) {
	path, err := splitKey(key)
	if err != nil {
		return nil, err
	}
	root, err := parseDoc(doc)
	if err != nil {
		return nil, err
	}

	m := root.Content[0]
	for _, seg := range path[:len(path)-1] {
		m = childMapping(m, seg)
	}
	setScalar(m, path[len(path)-1], value)

	return render(root)
}

// Unset removes a key, and any mapping it leaves empty.
//
// The cleanup matters: a `controllers.sca.mend` left behind as an empty mapping after its last
// setting is removed is not the same file as one that never mentioned mend, and the difference
// shows up later as a scanner block that exists and configures nothing.
func Unset(doc []byte, key string) ([]byte, error) {
	path, err := splitKey(key)
	if err != nil {
		return nil, err
	}
	root, err := parseDoc(doc)
	if err != nil {
		return nil, err
	}
	removePath(root.Content[0], path)
	return render(root)
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
		return v
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

// setScalar sets or replaces a scalar, leaving any comment on the key in place.
func setScalar(m *yaml.Node, key, value string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1].Kind = yaml.ScalarNode
			m.Content[i+1].Tag = scalarTag(value)
			m.Content[i+1].Value = value
			m.Content[i+1].Content = nil
			m.Content[i+1].Style = 0
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: scalarTag(value), Value: value})
}

// scalarTag keeps a version like "0.69.3" a string while letting true/false and numbers be
// themselves — `enabled: "true"` is not the same setting as `enabled: true`, and a config file
// that quietly turns one into the other is worse than one that refuses to write.
func scalarTag(v string) string {
	switch strings.ToLower(v) {
	case "true", "false":
		return "!!bool"
	}
	// Integer before float: "30" round-trips through both, and %g would make it 30.0 — a
	// timeout that reads differently from the one that was typed.
	if i, err := strconv.ParseInt(v, 10, 64); err == nil && strconv.FormatInt(i, 10) == v {
		return "!!int"
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil && strconv.FormatFloat(f, 'g', -1, 64) == v {
		return "!!float"
	}
	return "!!str"
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
