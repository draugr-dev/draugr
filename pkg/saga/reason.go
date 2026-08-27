package saga

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Reasoned is a policy value together with the argument somebody made for it.
//
// Every value a descriptor sets is a decision, and the decision outlives whoever took it. A
// severity threshold, a priority band, a component's exposure — each of them changes what a scan
// reports and what fails a build, and none of them says why anybody wanted it. The reader who
// meets the consequence six months later is not the person who chose it.
//
// A YAML comment is the obvious place to put that argument, and it is the wrong one: it is not
// addressable, so nothing can show it beside the rule it explains, and it does not survive the
// descriptor being merged and re-serialized — which is what happens before a run is published.
// A reason has to be a value to travel.
//
// So a rule may be written twice over. The short form is the value alone, unchanged and still the
// common case:
//
//	failOnPriority: P1
//
// The long form carries the reason with it:
//
//	failOnPriority:
//	  value: P1
//	  reason: >-
//	    Severity rates a flaw in the abstract. Priority folds in what this
//	    descriptor says about the component it was found in.
//
// The two are the same rule. A descriptor written before the long form existed keeps its exact
// bytes through a merge, because a value with no reason marshals back to the scalar it came from.
type Reasoned[T ~string] struct {
	// Value is the rule itself — the band, the level, the threshold.
	Value T
	// Reason is why somebody set it. Empty when the short form was used.
	Reason string
}

// String returns the value, so a Reasoned reads as its rule in a message.
func (r Reasoned[T]) String() string { return string(r.Value) }

// IsZero reports whether nothing was set, which is what `omitempty` asks. Without it a rule
// nobody wrote would marshal as an empty string and appear in the descriptor as a rule somebody
// deliberately cleared.
func (r Reasoned[T]) IsZero() bool { return r.Value == "" && r.Reason == "" }

// reasonedKeys are the only keys the long form takes, named in the error when another appears.
const reasonedKeys = "`value` and `reason`"

// UnmarshalYAML accepts either form: the value on its own, or a mapping of value and reason.
//
// Anything else is refused by name rather than ignored. A misspelled key in a policy block is a
// rule somebody believes is in force and is not, and the only moment that is cheap to notice is
// the one where the file is read.
func (r *Reasoned[T]) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		r.Value, r.Reason = T(s), ""
		return nil

	case yaml.MappingNode:
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
				return fmt.Errorf("line %d: unknown key %q — the long form takes %s",
					key.Line, key.Value, reasonedKeys)
			}
		}
		if !haveValue {
			return fmt.Errorf("line %d: written as a mapping but with no `value` — the long form takes %s",
				n.Line, reasonedKeys)
		}
		// The long form exists to carry the argument. Written without one it is the short form
		// with extra punctuation, and it reads on the page as a rule whose reason went missing
		// rather than one that never had it.
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("line %d: written as a mapping but with no `reason` — write the value on its own if there is nothing to say",
				n.Line)
		}
		r.Value, r.Reason = T(value), reason
		return nil
	}
	return fmt.Errorf("line %d: expected a value or a mapping of %s", n.Line, reasonedKeys)
}

// MarshalYAML writes the short form when there is no reason, so a descriptor that never used the
// long form round-trips byte for byte — and its digest, which is taken over these bytes, does not
// move because a field changed shape in Go.
func (r Reasoned[T]) MarshalYAML() (any, error) {
	if r.Reason == "" {
		return string(r.Value), nil
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

// Unstated is a value nobody wrote an argument for — the short form, and still the common case.
//
// Not the same thing as a surveyor's Fragment.ExposureReasons, which explains what topology a
// *proposed* value was read from and is deliberately never serialized. That is evidence about a
// guess, shown while somebody reviews it; this is a decision, and it outlives the review.
func Unstated[T ~string](value T) Reasoned[T] { return Reasoned[T]{Value: value} }
