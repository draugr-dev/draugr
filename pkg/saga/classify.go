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
	enc.SetIndent(Indent)
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
		if m.Content[i].Value != key {
			continue
		}
		// A rule is a mapping of value and an optional reason. Write into its `value` and leave
		// the argument alone: overwriting the mapping would delete somebody's reasoning as a side
		// effect of re-classifying, and the file would look right afterwards.
		if node := m.Content[i+1]; node.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(node.Content); j += 2 {
				if node.Content[j].Value == "value" {
					node.Content[j+1].Value = val
					node.Content[j+1].Tag = "!!str"
					node.Content[j+1].Style = 0
					return
				}
			}
		}
		// Anything else here is a rule written the older way, as the value on its own — a file
		// Draugr refuses to load, so this is reached only by a caller holding raw bytes.
		// Replacing it with the shape a rule has now is the repair.
		m.Content[i+1] = ruleNode(val)
		return
	}
	pair := []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, ruleNode(val)}
	idx := len(m.Content)
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == afterKey {
			idx = i + 2
			break
		}
	}
	m.Content = append(m.Content[:idx:idx], append(pair, m.Content[idx:]...)...)
}

// ruleNode builds `{value: <val>}` — the shape a rule has, with no reason, because a tool that
// classified a component has no argument to offer. The place for one is there for a person.
func ruleNode(val string) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "value"},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: val},
	}}
}
