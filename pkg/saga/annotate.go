package saga

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// AnnotateExposures writes what each named component's `exposure` was read from into the rule's
// own `reason`.
//
// A proposed exposure and a decided one are the same word in a file, and the value decides
// whether a finding is reported as P1 or P3. The survey says which ones it guessed on the way out
// — but that is a terminal that scrolls, and the review happens later, in an editor, by someone
// who may not have run the command. The evidence has to be where the value is:
//
//	exposure:
//	  value: public
//	  reason: an Ingress routes into it
//
// In the rule rather than in a trailing comment, which is where this used to put it. A comment is
// read by the person reviewing the file and by nobody afterwards: descriptors are merged and
// re-serialized before a run is published, and it does not survive that. Written as the reason,
// the evidence for a guess reaches the report the guess went on to shape — and if somebody
// decides the exposure is right, the argument for it is already written down.
//
// Only components in reasons are touched, so a value somebody decided is left alone rather than
// described as a guess. Written through the YAML node tree, so nothing else in the document
// moves.
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
		if reason := reasons[name.Value]; reason != "" && setRuleReason(exposure, reason) {
			annotated = true
		}
	}
	// Re-encoding normalizes formatting, so a document with nothing to say is returned exactly as
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

// setRuleReason writes a rule's `reason`, replacing one already there and adding one when there
// is none. It reports whether the document changed.
//
// A rule written any other way is left alone: this runs over a file somebody is about to review,
// and a survey rewriting a shape it did not expect is worse than one that says nothing.
func setRuleReason(rule *yaml.Node, reason string) bool {
	if rule.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(rule.Content); i += 2 {
		if rule.Content[i].Value == "reason" {
			rule.Content[i+1].Value = reason
			rule.Content[i+1].Tag = "!!str"
			rule.Content[i+1].Style = 0
			return true
		}
	}
	rule.Content = append(rule.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "reason"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: reason})
	return true
}
