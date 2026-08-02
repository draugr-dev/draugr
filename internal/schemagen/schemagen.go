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
