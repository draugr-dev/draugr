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
// way out. But that is a terminal that scrolls, and the review happens later, in an editor, by
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

// AnnotateSigners adds a trailing comment to each named signer, saying which image's signature it
// was read from.
//
// A signer is a statement about who is trusted to sign, so somebody reviewing one is accepting a
// policy rather than correcting an inventory. The question they have is where it came from, and
// the descriptor is where they will be when they ask it:
//
//   - name: acme-ci   # read from the signature on ghcr.io/acme/api:1.0
//
// Only signers in reasons are touched, so one written by hand is left without a comment rather
// than described as something a survey found.
func AnnotateSigners(data []byte, reasons map[string]string) ([]byte, error) {
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
	config := mappingValue(root.Content[0], "config")
	if config == nil {
		return data, nil
	}
	controls := mappingValue(config, "controls")
	if controls == nil {
		return data, nil
	}
	provenance := mappingValue(controls, "provenance")
	if provenance == nil {
		return data, nil
	}
	signers := mappingValue(provenance, "signers")
	if signers == nil || signers.Kind != yaml.SequenceNode {
		return data, nil
	}

	annotated := false
	for _, signer := range signers.Content {
		if signer.Kind != yaml.MappingNode {
			continue
		}
		name := mappingValue(signer, "name")
		if name == nil {
			continue
		}
		if reason := reasons[name.Value]; reason != "" {
			name.LineComment = reason
			annotated = true
		}
	}
	if !annotated {
		return data, nil
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

// AnnotateOrigins adds a trailing comment to each classification value in a resolved descriptor,
// naming the file that supplied it:
//
//	exposure: internal # from services/payments/draugr.saga-fragment.yaml
//
// origins is Resolved.Origins. Exposure, criticality and builtBy are annotated, and each label
// under its key. A value with no entry in origins is left without a comment.
func AnnotateOrigins(data []byte, origins map[string]map[string]string) ([]byte, error) {
	if len(origins) == 0 {
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
	mark := func(value *yaml.Node, source string) {
		if value != nil && source != "" {
			value.LineComment = "from " + source
			annotated = true
		}
	}
	for _, comp := range comps.Content {
		name := mappingValue(comp, "name")
		if name == nil {
			continue
		}
		fields := origins[name.Value]
		for _, f := range []string{"exposure", "criticality", "builtBy"} {
			mark(mappingValue(comp, f), fields[f])
		}
		labels := mappingValue(comp, "labels")
		if labels == nil || labels.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(labels.Content); i += 2 {
			mark(labels.Content[i+1], fields["labels."+labels.Content[i].Value])
		}
	}
	if !annotated {
		return data, nil
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
