package plugin

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Option is one setting a scanner accepts under its block in the Saga.
//
// Derived from the scanner's declared ConfigSchema rather than maintained beside it, so what a
// tool prints and what the engine enforces cannot disagree. A list of options kept by hand drifts
// from the schema the first time an option is added, and the drift is invisible: both halves
// look right on their own.
type Option struct {
	// Name is the descriptor key, as written under controllers.<control>.<scanner>.
	Name string `json:"name"`
	// Type is the JSON Schema type: string, boolean, integer, number, array or object.
	Type string `json:"type,omitempty"`
	// Description says what the option does and what it defaults to.
	Description string `json:"description,omitempty"`
	// Required reports whether the scanner refuses to run without it.
	Required bool `json:"required,omitempty"`
	// Enum lists the accepted values, when the schema constrains them.
	Enum []string `json:"enum,omitempty"`
}

// Options reports the settings a scanner accepts, sorted by name, from its declared ConfigSchema.
//
// An empty or unparseable schema yields no options. That is not the same as "takes nothing": a
// scanner that accepts no settings still declares an object schema with no properties, which is
// what makes an unknown key an error rather than a silent drop. Callers wanting to tell the two
// apart should check the schema's length themselves.
func Options(schema json.RawMessage) []Option {
	if len(schema) == 0 {
		return nil
	}
	var node struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Type        string `json:"type"`
			Description string `json:"description"`
			Enum        []any  `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &node); err != nil {
		return nil
	}
	required := make(map[string]bool, len(node.Required))
	for _, r := range node.Required {
		required[r] = true
	}
	out := make([]Option, 0, len(node.Properties))
	for name, prop := range node.Properties {
		opt := Option{
			Name:        name,
			Type:        prop.Type,
			Description: prop.Description,
			Required:    required[name],
		}
		for _, e := range prop.Enum {
			opt.Enum = append(opt.Enum, fmt.Sprint(e))
		}
		out = append(out, opt)
	}
	// Required options first, then alphabetical: a reader scanning the list wants to know what
	// they must supply before what they may.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Required != out[j].Required {
			return out[i].Required
		}
		return out[i].Name < out[j].Name
	})
	return out
}
