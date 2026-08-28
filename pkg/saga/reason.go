package saga

import (
	"fmt"
	"reflect"
	"sort"
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
// ways depending on whether anybody had something to say. A rule written the older way, as the
// value on its own, is refused with the two lines that replace it.
type Reasoned[T ~string] struct {
	// Value is the rule itself — the band, the level, the threshold.
	Value T
	// Reason is why somebody set it. Optional, and empty when nobody wrote one.
	Reason string
	// short records that the descriptor wrote this rule as the value on its own — the shape a
	// rule had before it could carry a reason. Kept so the loader can say so once, by name; it is
	// never written back, because what Draugr emits is the shape a rule has now.
	short bool
}

// WrittenShort reports that this rule was written as a bare value rather than as a rule. It is
// how Model.Deprecations finds them without every caller having to know where rules live.
func (r Reasoned[T]) WrittenShort() bool { return r.short }

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
		// The shape a rule had before it could carry a reason. Accepted until the removal date so
		// an upgrade does not stop every existing pipeline on the same afternoon, and reported by
		// Model.Deprecations so nobody finds out on the date instead.
		var value string
		if err := n.Decode(&value); err != nil {
			return err
		}
		r.Value, r.Reason, r.short = T(value), "", true
		return nil
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

// ruleShapeWindow says how long a rule written as a bare value keeps loading.
//
// One release, and no date. The window exists for one reason: a descriptor cannot be converted
// until a published Draugr can read the new shape, and this repository's own is scanned by the
// latest release. Naming a date would promise a window nobody needs and this project does not
// intend to keep — the shape is gone in the next release, and the notice says so rather than
// pointing at a month.
const ruleShapeWindow = "stops loading in the next release"

// RuleDeprecations names every rule in a descriptor still written as a bare value.
//
// Found by walking the model rather than by a list somebody maintains: a rule added later would
// otherwise be missing from the notice, and the first anybody would hear of it is the release
// that stops loading it.
func RuleDeprecations(model any) []string {
	var found []string
	walkRules(reflect.ValueOf(model), "", &found)
	sort.Strings(found)
	return found
}

// writtenShort is what a rule looks like to the walk below.
type writtenShort interface{ WrittenShort() bool }

func walkRules(v reflect.Value, path string, found *[]string) {
	if !v.IsValid() {
		return
	}
	if v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		walkRules(v.Elem(), path, found)
		return
	}
	if v.CanInterface() {
		if r, ok := v.Interface().(writtenShort); ok {
			if r.WrittenShort() {
				*found = append(*found, path)
			}
			return
		}
	}
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			walkRules(v.Field(i), joinRulePath(path, name), found)
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			walkRules(v.Index(i), fmt.Sprintf("%s[%d]", path, i), found)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			walkRules(v.MapIndex(k), joinRulePath(path, fmt.Sprint(k.Interface())), found)
		}
	}
}

func joinRulePath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
