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
	// Meanings says what each value in Enum does, keyed by the value, for the ones whose schema
	// explains them.
	//
	// A list of values a reader has to guess at is a list they guess wrong. `observe`, `warn` and
	// `fail` are three words that each name a policy, and an editor offering the three with no
	// gloss has told somebody the spelling and nothing else.
	Meanings map[string]string `json:"meanings,omitempty"`
	// Pattern is the regular expression a string value must match, when the schema gives one.
	Pattern string `json:"pattern,omitempty"`
	// Schema is the option's declared JSON Schema, exactly as the plugin wrote it, nested items and
	// closed objects included. The Saga schema publishes this rather than a summary of it, so an
	// editor holds a descriptor to the same rules ValidateConfig does.
	Schema json.RawMessage `json:"-"`
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
			Pattern     string `json:"pattern"`
			// ReadOnly marks a key a controller writes into the job config and a descriptor may
			// not. The scanner declares it because the engine holds a job's config to this
			// schema; it is not something anybody chooses, so it is not offered as an option.
			ReadOnly bool `json:"readOnly"`
			// AnyOf carries an enum whose values explain themselves, one const per variant. The
			// shape the descriptor's own enums use, so a scanner's and the Saga's read alike.
			AnyOf []struct {
				Const       any    `json:"const"`
				Description string `json:"description"`
			} `json:"anyOf"`
			// Items carries an array option's element constraint. Without reading it, the accepted values
			// of a list are lost, and a caller rendering the option shows none, while the validator still
			// enforces them. The two disagreeing is the failure to avoid.
			Items struct {
				Enum []any `json:"enum"`
			} `json:"items"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &node); err != nil {
		return nil
	}
	var raw struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	_ = json.Unmarshal(schema, &raw) // the same document, which just decoded
	required := make(map[string]bool, len(node.Required))
	for _, r := range node.Required {
		required[r] = true
	}
	out := make([]Option, 0, len(node.Properties))
	for name, prop := range node.Properties {
		if prop.ReadOnly {
			continue
		}
		opt := Option{
			Name:        name,
			Type:        prop.Type,
			Description: prop.Description,
			Required:    required[name],
			Pattern:     prop.Pattern,
			Schema:      raw.Properties[name],
		}
		// An array constrains its elements; a scalar constrains itself. Either way these are the
		// values the option accepts, which is the question a caller is asking.
		values := prop.Enum
		if len(values) == 0 {
			values = prop.Items.Enum
		}
		for _, e := range values {
			opt.Enum = append(opt.Enum, fmt.Sprint(e))
		}
		for _, v := range prop.AnyOf {
			if v.Const == nil {
				continue
			}
			val := fmt.Sprint(v.Const)
			opt.Enum = append(opt.Enum, val)
			if v.Description != "" {
				if opt.Meanings == nil {
					opt.Meanings = map[string]string{}
				}
				opt.Meanings[val] = v.Description
			}
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
