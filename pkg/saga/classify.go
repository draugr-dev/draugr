package saga

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Classification is a component's risk tags.
type Classification struct {
	Exposure    Exposure
	Criticality Criticality
}

// WriteClassifications sets each named component's exposure and criticality in the raw Saga
// bytes and returns the updated document. It operates on the parsed YAML nodes, so comments
// and ${{ VAR }} tokens are preserved (values are not substituted); indentation is normalized
// to two spaces. Components not present in class are left untouched. New keys are inserted
// right after the component's name for readability; existing values are updated in place.
func WriteClassifications(data []byte, class map[string]Classification) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse saga: %w", err)
	}
	if len(root.Content) == 0 {
		return data, nil
	}
	comps := mappingValue(root.Content[0], "components")
	if comps == nil || comps.Kind != yaml.SequenceNode {
		return data, nil
	}
	for _, comp := range comps.Content {
		if comp.Kind != yaml.MappingNode {
			continue
		}
		name := mappingValue(comp, "name")
		if name == nil {
			continue
		}
		c, ok := class[name.Value]
		if !ok {
			continue
		}
		setScalarAfter(comp, "name", "exposure", string(c.Exposure))
		setScalarAfter(comp, "exposure", "criticality", string(c.Criticality))
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, fmt.Errorf("encode saga: %w", err)
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

// mappingValue returns the value node for key in a mapping node, or nil.
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

// setScalarAfter sets key=val in the mapping node: it updates the value in place if key
// already exists, otherwise inserts the key/value pair immediately after the pair whose key
// is afterKey (appending if afterKey is absent).
func setScalarAfter(m *yaml.Node, afterKey, key, val string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1].Value = val
			m.Content[i+1].Tag = "!!str"
			m.Content[i+1].Style = 0
			return
		}
	}
	pair := []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: val},
	}
	idx := len(m.Content)
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == afterKey {
			idx = i + 2
			break
		}
	}
	m.Content = append(m.Content[:idx:idx], append(pair, m.Content[idx:]...)...)
}
