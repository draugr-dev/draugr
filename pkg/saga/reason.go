package saga

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Reasoned is a policy value and, optionally, the argument somebody made for it.
//
// Every value a descriptor sets is a decision, and the decision outlives whoever took it. A
// severity threshold, a priority band, a component's exposure — each of them changes what a scan
// reports and what fails a build, and none of them said why anybody wanted it. The reader who
// meets the consequence six months later is not the person who chose it.
//
// A YAML comment is the obvious place to put that argument, and it is the wrong one: it is not
// addressable, so nothing can show it beside the rule it explains, and it does not survive the
// descriptor being merged and re-serialized — which is what happens before a run is published.
// A reason has to be a value to travel.
//
// So a rule is written as a value with a place for its reason:
//
//	failOnPriority:
//	  value: P1
//	  reason: >-
//	    Severity rates a flaw in the abstract. Priority folds in what this
//	    descriptor says about the component it was found in.
//
// The reason is optional; the shape is not. One rule has one schema — an editor can complete it,
// a reviewer knows where to look, and a reader never has to learn that this field is written two
// ways depending on whether anybody had something to say.
type Reasoned[T ~string] struct {
	// Value is the rule itself — the band, the level, the threshold.
	Value T
	// Reason is why somebody set it. Optional, and empty when nobody wrote one.
	Reason string
}

// String returns the value, so a Reasoned reads as its rule in a message.
func (r Reasoned[T]) String() string { return string(r.Value) }

// IsZero reports whether nothing was set, which is what `omitempty` asks. Without it a rule
// nobody wrote would marshal as an empty string and appear in the descriptor as a rule somebody
// deliberately cleared.
func (r Reasoned[T]) IsZero() bool { return r.Value == "" && r.Reason == "" }

// reasonedKeys are the only keys a rule takes, named in the error when another appears.
const reasonedKeys = "a required `value` and an optional `reason`"

// UnmarshalYAML reads the mapping of value and reason, and refuses anything else by name.
//
// A misspelled key in a policy block is a rule somebody believes is in force and is not, and the
// only moment that is cheap to notice is the one where the file is read.
func (r *Reasoned[T]) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		// The shape a rule had before it could carry a reason. Named as such and shown its
		// replacement: "expected a mapping" sends somebody to the schema to work out which
		// mapping, and the answer is two lines they can paste.
		return fmt.Errorf("line %d: a rule is written as a value with a place for its reason, not as the value on its own. Replace `%s` with:\n    value: %s\n    reason: >-        # optional\n      why this is set",
			n.Line, n.Value, n.Value)
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping of %s", n.Line, reasonedKeys)
	}

	var value, reason string
	var haveValue bool
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		switch key.Value {
		case "value":
			if err := val.Decode(&value); err != nil {
				return fmt.Errorf("line %d: value: %w", val.Line, err)
			}
			haveValue = true
		case "reason":
			if err := val.Decode(&reason); err != nil {
				return fmt.Errorf("line %d: reason: %w", val.Line, err)
			}
		default:
			return fmt.Errorf("line %d: unknown key %q — a rule takes %s",
				key.Line, key.Value, reasonedKeys)
		}
	}
	if !haveValue {
		return fmt.Errorf("line %d: no `value` — a rule takes %s", n.Line, reasonedKeys)
	}
	r.Value, r.Reason = T(value), strings.TrimSpace(reason)
	return nil
}

// MarshalYAML writes the one shape, reason included when there is one.
func (r Reasoned[T]) MarshalYAML() (any, error) {
	if r.Reason == "" {
		return struct {
			Value string `yaml:"value"`
		}{string(r.Value)}, nil
	}
	return struct {
		Value  string `yaml:"value"`
		Reason string `yaml:"reason"`
	}{string(r.Value), r.Reason}, nil
}

// Stated pairs a value with the argument for it, which is what the long form decodes to.
func Stated[T ~string](value T, reason string) Reasoned[T] {
	return Reasoned[T]{Value: value, Reason: reason}
}

// Unstated is a value nobody wrote an argument for, which is allowed and common.
//
// Not the same thing as a surveyor's Fragment.ExposureReasons, which explains what topology a
// *proposed* value was read from and is deliberately never serialized. That is evidence about a
// guess, shown while somebody reviews it; this is a decision, and it outlives the review.
func Unstated[T ~string](value T) Reasoned[T] { return Reasoned[T]{Value: value} }
