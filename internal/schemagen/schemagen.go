// Package schemagen keeps the Saga JSON Schema's knowledge of controls in step with the
// registry that actually answers for them.
//
// The control list used to be hand-written in the schema file, and it drifted two controls
// behind — an editor rejected descriptors that Draugr accepted, including Draugr's own. No test
// could have caught it: pkg/saga owns the schema and cannot import the registry without a cycle,
// so nothing was in a position to compare them. This package is that position.
//
// Generated rather than validated so the answer cannot be wrong: `go generate ./...` rewrites the
// file, and a test asserts that regenerating changes nothing.
package schemagen

import (
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"

	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// controlNameDef builds the `controlName` definition: every control the registry serves, each
// with the summary the controller gives `draugr controls`, so an editor shows the same
// description the CLI does.
func controlNameDef(reg *engine.Registry) map[string]any {
	type named struct{ name, summary string }
	var controls []named
	for _, c := range reg.Controllers() {
		info := c.Info()
		controls = append(controls, named{info.Name, info.Summary})
	}
	sort.Slice(controls, func(i, j int) bool { return controls[i].name < controls[j].name })

	variants := make([]any, 0, len(controls))
	for _, c := range controls {
		variants = append(variants, map[string]any{
			"const":       c.name,
			"description": c.summary,
		})
	}
	return map[string]any{
		"description": "A control this build of Draugr implements. A name that is not here is " +
			"rejected: a control Draugr cannot run is a check that will not happen, and a " +
			"descriptor should not be able to ask for one quietly.",
		"type":  "string",
		"anyOf": variants,
	}
}

// allowEffectsDef builds the `allowEffects` enum from the effect taxonomy.
//
// Generated for the same reason the control names are: the list was written out beside the
// taxonomy and the two drifted the moment a kind was added, leaving the schema rejecting a value
// the binary accepts. An editor that disagrees with Draugr is worse than one that says nothing.
func allowEffectsDef() map[string]any {
	kinds := plugin.EffectKinds()
	enum := make([]any, 0, len(kinds))
	var consent []string
	for _, k := range kinds {
		enum = append(enum, string(k))
		if k.RequiresConsent() {
			consent = append(consent, strconv.Quote(string(k)))
		}
	}
	return map[string]any{
		"description": "Scanner effects the project accepts. A scanner that does more to a " +
			"target than read it declares an effect; kinds that require consent (" +
			strings.Join(consent, ", ") + ") will not run unless listed here or allowed with " +
			"--allow-effects.",
		"type":  "array",
		"items": map[string]any{"type": "string", "enum": enum},
		// Listing a kind twice accepts nothing extra, so it is a typo rather than an intention.
		// Preserved from the hand-written definition this replaced — a generator that quietly
		// drops a constraint is worse than the drift it was written to fix.
		"uniqueItems": true,
	}
}

// Apply rewrites the generated parts of the schema document in place and returns the encoded
// result, formatted the way the checked-in file is.
func Apply(schemaJSON []byte, reg *engine.Registry) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(schemaJSON, &doc); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	defs, ok := doc["$defs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no $defs object")
	}
	defs["controlName"] = controlNameDef(reg)

	cfg, ok := defs["config"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no config definition")
	}
	props, ok := cfg["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema config has no properties")
	}
	props["allowEffects"] = allowEffectsDef()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// The file escapes non-ASCII, and rewriting every em dash in a generated diff would bury the
	// one line that actually changed.
	enc.SetEscapeHTML(true)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// FragmentSchema derives the Saga fragment's JSON Schema from the Saga's.
//
// Derived rather than maintained beside it, because two hand-written schemas drift — and the way
// drift shows up here is an editor rejecting a descriptor Draugr accepts, which is exactly what
// the checked-in-schema guard exists to prevent. Sharing `$defs` by construction means a change
// to a component or an exclusion reaches both schemas or neither.
//
// The transformation is the rule "a fragment adds scope or attributed suppressions, and cannot
// change policy", expressed so an editor can enforce it: only components, the restricted config,
// and further fragments survive.
func FragmentSchema(sagaJSON []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(sagaJSON, &doc); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	props, ok := doc["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no properties object")
	}

	doc["$id"] = "https://draugr.dev/schema/draugr.saga-fragment.schema.json"
	doc["title"] = "Draugr Saga fragment"
	doc["description"] = "A partial Draugr Saga: components and exclusions merged into the " +
		"descriptor that names it. A fragment adds scope or adds attributed suppressions; it " +
		"cannot change policy, so it carries no release, gate or controller settings."
	// A fragment requires nothing. One carrying only exclusions is a perfectly good fragment, and
	// so is one carrying only components.
	delete(doc, "required")

	kept := map[string]any{}
	for _, name := range []string{"components", "fragments"} {
		if v, found := props[name]; found {
			kept[name] = v
		}
	}
	kept["config"] = map[string]any{"$ref": "#/$defs/fragmentConfig"}
	doc["properties"] = kept

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
