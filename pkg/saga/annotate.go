package saga

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// AnnotateExposures adds a trailing comment to each named component's `exposure`, saying what the
// value was read from.
//
// A proposed exposure and a decided one are the same three characters in a file, and the value
// decides whether a finding is reported as P1 or P3. The survey says which ones it guessed on the
// way out — but that is a terminal that scrolls, and the review happens later, in an editor, by
// someone who may not have run the command. The reason has to be where the value is:
//
//	exposure: public   # an Ingress routes into it
//
// Only components in reasons are touched, so a value somebody decided is left without a comment
// rather than described as a guess. Written through the YAML node tree, so nothing else in the
// document moves.
func AnnotateExposures(data []byte, reasons map[string]string) ([]byte, error) {
	if len(reasons) == 0 {
		return data, nil
	}
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

	annotated := false
	for _, comp := range comps.Content {
		if comp.Kind != yaml.MappingNode {
			continue
		}
		name := mappingValue(comp, "name")
		exposure := mappingValue(comp, "exposure")
		if name == nil || exposure == nil {
			continue
		}
		if reason := reasons[name.Value]; reason != "" {
			exposure.LineComment = reason
			annotated = true
		}
	}
	// Re-encoding normalises formatting, so a document with nothing to say is returned exactly as
	// it arrived rather than rewritten to no purpose.
	if !annotated {
		return data, nil
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	// Encoding through a node tree is how the comments get attached; it must not reindent the
	// file as a side effect.
	enc.SetIndent(Indent)
	if err := enc.Encode(&root); err != nil {
		return nil, fmt.Errorf("encode saga: %w", err)
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}
