// Package schemagen keeps the Saga JSON Schema's knowledge of controls in step with the
// registry that actually answers for them.
//
// A hand-written control list in the schema file drifts behind the registry, and the symptom
// reaches a user as an editor rejecting a descriptor Draugr accepts — including Draugr's own. No
// test can catch that from either side: pkg/saga owns the schema and cannot import the registry
// without a cycle, so neither package is in a position to compare them. This one is.
//
// Generated rather than validated so the answer cannot be wrong: `go generate ./...` rewrites the
// file, and a test asserts that regenerating changes nothing.
package schemagen

import (
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"

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
	// The list shape, used on its own and again as the value of each environment.
	list := map[string]any{
		"type":  "array",
		"items": map[string]any{"type": "string", "enum": enum},
		// Listing a kind twice accepts nothing extra, so it is a typo rather than an intention.
		"uniqueItems": true,
	}
	return map[string]any{
		"description": "Scanner effects the project accepts. A scanner that does more to a " +
			"target than read it declares an effect; kinds that require consent (" +
			strings.Join(consent, ", ") + ") will not run unless listed here or allowed with " +
			"--allow-effects.",
		// Two shapes. A list accepts an effect in every environment; a mapping accepts it per
		// environment, which is what makes the permission match the decision — a scan allowed
		// against staging is not thereby allowed against production.
		"oneOf": []any{
			list,
			map[string]any{
				"type":                 "object",
				"description":          "Effects accepted per environment, keyed by the environment name a target declares. An environment with an empty list accepts nothing.",
				"additionalProperties": list,
				"propertyNames":        map[string]any{"pattern": `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`},
			},
		},
	}
}

// controlDefs builds one definition per control, naming the scanners that serve it and the
// options each accepts.
//
// Without this, an editor's help stops at the control name. `controllers.sast:` completes, and
// then nothing does — not `semgrep`, not `gosec`, not the options either takes — because the
// generic settings shape describes only `enabled` and accepts any key beside it. A reader is left
// guessing at exactly the layer that has the most to guess at: which scanners a control has, and
// what each one is willing to be told.
//
// The scanner blocks are keyed by the camelCase name a descriptor writes, not the scanner's own
// hyphenated name, because that is what the loader accepts. Getting that wrong would autocomplete
// a key the descriptor then rejects, which is worse than no completion at all.
//
// Closed rather than open. `additionalProperties: false` means an editor flags a scanner the
// control does not have, and an option a scanner does not take, at the moment it is typed — the
// same answer `draugr validate` gives, arriving sooner. The engine still validates at plan time;
// this is the same rule stated where it can be acted on.
func controlDefs(reg *engine.Registry) map[string]map[string]any {
	serving := map[string][]plugin.ScannerInfo{}
	for _, sc := range reg.Scanners() {
		info := sc.Info()
		if info.Reachability {
			// Serves the control, but is enabled by config.reachability rather than from its
			// scanner block. Offering it here would have an editor complete a key the loader
			// rejects — which is worse than not offering it, because the descriptor looks right
			// until it is run.
			continue
		}
		for _, control := range info.Controls {
			serving[control] = append(serving[control], info)
		}
	}

	out := map[string]map[string]any{}
	for _, ctrl := range reg.Controllers() {
		name := ctrl.Info().Name
		scanners := serving[name]
		sort.Slice(scanners, func(i, j int) bool { return scanners[i].Name < scanners[j].Name })

		props := map[string]any{
			"enabled": map[string]any{
				"type": "boolean",
				"description": "Whether this control runs. An entry with no `enabled` key counts " +
					"as enabled; an absent entry means disabled.",
			},
		}
		defaults := map[string]bool{}
		for _, d := range ctrl.Info().DefaultScanners {
			defaults[d] = true
		}
		for _, info := range scanners {
			props[controllers.ScannerConfigKey(info.Name)] = scannerDef(info, defaults[info.Name])
		}
		out[name] = map[string]any{
			"type":                 "object",
			"description":          ctrl.Info().Summary,
			"properties":           props,
			"additionalProperties": false,
		}
	}
	return out
}

// scannerDef describes one scanner's block: `enabled`, plus the options it declares.
//
// The options come from the scanner's own ConfigSchema, so what an editor offers and what the
// engine accepts are the same list by construction. A scanner that accepts nothing gets a block
// with only `enabled` — which is a statement, not an omission, and closing it is what turns "this
// scanner takes no options" from something you discover by being rejected into something you see
// while typing.
func scannerDef(info plugin.ScannerInfo, isDefault bool) map[string]any {
	enabled := "Run this scanner. "
	if isDefault {
		enabled += "It is a default for this control, so it runs unless set to false."
	} else {
		enabled += "It is opt-in, so it runs only when set to true."
	}
	props := map[string]any{
		"enabled": map[string]any{"type": "boolean", "description": enabled},
	}
	for _, opt := range plugin.Options(info.ConfigSchema) {
		props[opt.Name] = optionDef(opt)
	}
	def := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if info.Origin != "" {
		def["description"] = fmt.Sprintf("%s — published by %s.", info.Name, info.Origin)
	}
	return def
}

// optionDef renders one declared option for the schema, keeping its description so an editor
// shows the same sentence `draugr controls --options` prints.
func optionDef(opt plugin.Option) map[string]any {
	d := map[string]any{"description": opt.Description}
	if opt.Type != "" {
		d["type"] = opt.Type
	}
	if len(opt.Enum) > 0 {
		vals := make([]any, len(opt.Enum))
		for i, e := range opt.Enum {
			vals[i] = e
		}
		if opt.Type == "array" {
			d["items"] = map[string]any{"enum": vals}
		} else {
			d["enum"] = vals
		}
	}
	return d
}

// reportFormatDef lists the report formats this build can render.
//
// Generated for the same reason the control list is: a hand-written copy drifts, and the way
// drift shows up is an editor rejecting a descriptor Draugr accepts. `template` is added because
// it is selectable through `--format` with `--template`, but is not a registered reporter.
func reportFormatDef() map[string]any {
	formats := append(report.Formats(), "template")
	sort.Strings(formats)
	vals := make([]any, len(formats))
	for i, f := range formats {
		vals[i] = f
	}
	return map[string]any{
		"type":        "string",
		"description": "Report format to render.",
		"enum":        vals,
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

	// Per-control definitions, and a `controllers` node that points each control name at its own.
	// The generic `controllerSettings` stays as the fallback for anything not in the registry, so
	// a schema consumer never hits an unresolvable ref.
	byControl := controlDefs(reg)
	named := make(map[string]any, len(byControl))
	for name, def := range byControl {
		key := "control_" + name
		defs[key] = def
		named[name] = map[string]any{"$ref": "#/$defs/" + key}
	}
	ctrls, ok := defs["controllers"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no controllers definition")
	}
	ctrls["properties"] = named

	cfg, ok := defs["config"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no config definition")
	}
	props, ok := cfg["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema config has no properties")
	}
	props["allowEffects"] = allowEffectsDef()

	rc, ok := defs["reportConfig"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no reportConfig definition")
	}
	rcProps, ok := rc["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("reportConfig has no properties")
	}
	rcProps["format"] = reportFormatDef()

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
