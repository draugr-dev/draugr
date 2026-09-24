// Package schemagen keeps the Saga JSON Schema's knowledge of controls in step with the
// registry that actually answers for them.
//
// A hand-written control list in the schema file drifts behind the registry, and the symptom
// reaches a user as an editor rejecting a descriptor Draugr accepts, including Draugr's own. No
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
	"github.com/draugr-dev/draugr/pkg/saga"

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
	// anyOf of const rather than a plain enum, so an editor shows what each kind means beside the
	// completion. Consenting to something is the one place a reader must not be guessing at the
	// word, and the taxonomy already explains itself.
	enum := make([]any, 0, len(kinds))
	var consent []string
	for _, k := range kinds {
		desc := k.Describe()
		if k.RequiresConsent() {
			desc += "; will not run unless allowed"
		}
		enum = append(enum, map[string]any{"const": string(k), "description": desc})
		if k.RequiresConsent() {
			consent = append(consent, strconv.Quote(string(k)))
		}
	}
	return map[string]any{
		"description": "Scanner effects the project accepts. A scanner that does more to a " +
			"target than read it declares an effect; kinds that require consent (" +
			strings.Join(consent, ", ") + ") will not run unless listed here or allowed with " +
			"--allow-effects.",
		// One shape. It was briefly also a mapping keyed by environment, which put two shapes
		// behind one key and made how strict a permission is depend on which one an author
		// reached for. A scan that may do different things to different targets is a second
		// descriptor.
		"type":  "array",
		"items": map[string]any{"type": "string", "anyOf": enum},
		// Listing a kind twice accepts nothing extra, so it is a typo rather than an intention.
		"uniqueItems": true,
	}
}

// analyzersDef builds the `config.reachability.analyzers` enum from the registry.
//
// Generated for the reason the control names and the effect kinds are, arriving at it from the
// other side: the schema said `type: string` and accepted anything, while the loader refuses a
// name no scanner answers to and offers the nearest one it has. An editor that accepts a
// descriptor Draugr rejects teaches somebody the name is fine, and the correction arrives from CI
// instead of from the line they are typing.
//
// Not closed by hand: a scanner declares `Reachability` on its own info, and this reads the same
// flag the planner does, so a new analyzer is offered the moment it is registered.
func analyzersDef(reg *engine.Registry) map[string]any {
	var names []string
	for _, sc := range reg.Scanners() {
		if info := sc.Info(); info.Reachability {
			names = append(names, info.Name)
		}
	}
	sort.Strings(names)
	enum := make([]any, 0, len(names))
	for _, n := range names {
		enum = append(enum, n)
	}
	return map[string]any{
		"description": "Tools that decide reachability, e.g. `govulncheck`. Named rather than " +
			"inferred, so the descriptor says which tool reached the verdict and `draugr doctor` " +
			"can say what to install. An analyzer adds no findings: it ranks findings you " +
			"already have downward.",
		"type":  "array",
		"items": map[string]any{"type": "string", "enum": enum},
		// Naming one twice enables nothing extra, so it is a typo rather than an intention. The
		// planner already deduplicates; this says so where it is being written.
		"uniqueItems": true,
	}
}

// infraKindDef builds the `infrastructure.kind` values from the surfaces Draugr audits.
//
// It said `type: string` and accepted anything, while the planner drops a kind nothing serves, so
// a component declaring `kind: k8s` was scanned for everything except the infrastructure it named
// and read as covered. `operatedBy`, the field beside it, has had a values list and a validation
// error for exactly this reason since it was added.
//
// The `anyOf` of `const` shape rather than a plain enum, because that is what makes an editor show
// the description beside each completion, the same as `exposure` and `criticality`.
func infraKindDef() map[string]any {
	one := make([]any, 0, len(saga.InfrastructureKinds))
	for _, k := range saga.InfrastructureKinds {
		one = append(one, map[string]any{
			"const":       k,
			"description": "A Kubernetes cluster, audited against a CIS benchmark.",
		})
	}
	return map[string]any{
		"description": "The infrastructure surface to audit. `ref` names the concrete instance.",
		"type":        "string",
		"anyOf":       one,
	}
}

// controlDefs builds one definition per control, naming the scanners that serve it and the
// options each accepts.
//
// Without this, an editor's help stops at the control name. `controllers.sast:` completes, and
// then nothing does, not `semgrep`, not `gosec`, not the options either takes, because the
// generic settings shape describes only `enabled` and accepts any key beside it. A reader is left
// guessing at exactly the layer that has the most to guess at: which scanners a control has, and
// what each one is willing to be told.
//
// The scanner blocks are keyed by the camelCase name a descriptor writes, not the scanner's own
// hyphenated name, because that is what the loader accepts. Getting that wrong would autocomplete
// a key the descriptor then rejects, which is worse than no completion at all.
//
// Closed rather than open. `additionalProperties: false` means an editor flags a scanner the
// control does not have, and an option a scanner does not take, at the moment it is typed. The
// same answer `draugr validate` gives, arriving sooner. The engine still validates at plan time;
// this is the same rule stated where it can be acted on.
func controlDefs(reg *engine.Registry) map[string]map[string]any {
	serving := map[string][]plugin.ScannerInfo{}
	for _, sc := range reg.Scanners() {
		info := sc.Info()
		if info.Reachability {
			// Serves the control, but is enabled by config.reachability rather than from its scanner
			// block. Offering it here would have an editor complete a key the loader rejects. Which is
			// worse than not offering it, because the descriptor looks right until it is run.
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
		// The control's own settings, before the scanner blocks, so `deny` under `licenses` is
		// offered where a descriptor writes it rather than flagged as a scanner that does not exist.
		for _, opt := range plugin.Options(ctrl.Info().OptionSchema) {
			props[opt.Name] = optionDef(opt)
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

// fragmentControlsDef describes what a fragment may set under `config.controls`.
//
// Built from the same registry and the same option definitions as the descriptor's own controls
// block, filtered by saga.FragmentControlOptions, so an editor offers exactly what the decoder
// accepts. Writing the short list out by hand would be a second copy of a rule whose whole value
// is that there is one of it.
//
// No `enabled` key and no scanner blocks, which is the point: a fragment contributes to a control
// and cannot decide whether it runs or what runs it.
func fragmentControlsDef(reg *engine.Registry) map[string]any {
	options := map[string]plugin.Option{}
	summaries := map[string]string{}
	for _, ctrl := range reg.Controllers() {
		info := ctrl.Info()
		summaries[info.Name] = info.Summary
		for _, opt := range plugin.Options(info.OptionSchema) {
			options[info.Name+"."+opt.Name] = opt
		}
	}

	props := map[string]any{}
	for _, control := range saga.FragmentControls() {
		allowed := map[string]any{}
		for _, name := range saga.FragmentControlOptionsFor(control) {
			opt, found := options[control+"."+name]
			if !found {
				continue
			}
			allowed[name] = optionDef(opt)
		}
		if len(allowed) == 0 {
			continue
		}
		props[control] = map[string]any{
			"type":                 "object",
			"description":          summaries[control],
			"properties":           allowed,
			"additionalProperties": false,
		}
	}
	return map[string]any{
		"type": "object",
		"description": "Control settings this fragment contributes, appended to the descriptor's " +
			"own. Only settings that can add findings appear here; a fragment cannot switch a " +
			"control off, change what is trusted, or change what a finding is worth.",
		"properties":           props,
		"additionalProperties": false,
	}
}

// scannerDef describes one scanner's block: `enabled`, plus the options it declares.
//
// The options come from the scanner's own ConfigSchema, so what an editor offers and what the
// engine accepts are the same list by construction. A scanner that accepts nothing gets a block
// with only `enabled`. Which is a statement, not an omission, and closing it is what turns "this
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
		def["description"] = fmt.Sprintf("%s, published by %s.", info.Name, info.Origin)
	}
	return def
}

// optionDef publishes one declared option as the plugin declared it.
//
// Verbatim rather than rebuilt from a summary, because a summary loses whatever it does not name,
// such as the closed objects inside a list, and an editor would then accept keys `draugr validate`
// refuses. The plugin's schema is the one ValidateConfig enforces, so publishing it is what makes
// the two agree by construction.
func optionDef(opt plugin.Option) map[string]any {
	d := map[string]any{}
	if len(opt.Schema) > 0 && json.Unmarshal(opt.Schema, &d) == nil {
		delete(d, "readOnly")
		return d
	}
	d["description"] = opt.Description
	if opt.Type != "" {
		d["type"] = opt.Type
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
		vals[i] = map[string]any{"const": f, "description": report.Summary(f)}
	}
	return map[string]any{
		"type":        "string",
		"description": "Report format to render.",
		"anyOf":       vals,
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

	rch, ok := defs["reachabilityConfig"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no reachabilityConfig definition")
	}
	rchProps, ok := rch["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("reachabilityConfig has no properties")
	}
	rchProps["analyzers"] = analyzersDef(reg)

	infra, ok := defs["infrastructure"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no infrastructure definition")
	}
	infraProps, ok := infra["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("infrastructure has no properties")
	}
	infraProps["kind"] = infraKindDef()

	rc, ok := defs["reportConfig"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no reportConfig definition")
	}
	rcProps, ok := rc["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("reportConfig has no properties")
	}
	rcProps["format"] = reportFormatDef()

	fc, ok := defs["fragmentConfig"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no fragmentConfig definition")
	}
	fcProps, ok := fc["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("fragmentConfig has no properties")
	}
	defs["fragmentControls"] = fragmentControlsDef(reg)
	fcProps["controls"] = map[string]any{"$ref": "#/$defs/fragmentControls"}

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
// Derived rather than maintained beside it, because two hand-written schemas drift. And the way
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
	// Its own note, replacing the Saga schema's. That one tells a reader which definitions are
	// safe to edit by hand, and none of them are here: this file is derived in full, so the
	// inherited advice would send somebody to edit a file that is overwritten on the next
	// `go generate`.
	//
	// What a reader of a fragment needs, and a pointer for the one person editing this repository.
	// The long form is a contributing page rather than a line every editor loads and the schema
	// site serves: the same reason the Saga schema's own comment is one line.
	doc["$comment"] = "A fragment adds scope or attributed suppressions and cannot change policy, " +
		"which is the rule this file expresses so an editor can enforce it. Generated in full; " +
		"before editing it by hand, read docs/contributing/schema.md in the draugr repository."

	props, ok := doc["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no properties object")
	}

	doc["$id"] = "https://draugr.dev/schema/draugr.saga-fragment.schema.json"
	doc["title"] = "Draugr Saga fragment"
	doc["description"] = "A partial Draugr Saga: components, exclusions and a short list of " +
		"control settings, merged into the descriptor that names it. A fragment adds scope, adds " +
		"attributed suppressions, or contributes a setting that can only add findings; it cannot " +
		"change policy, so it carries no release or gate, and cannot switch a control off."
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
