package schemagen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// generated decodes the schema the registry produces, which is what an editor consumes.
func generated(t *testing.T) map[string]any {
	t.Helper()
	current, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	out, err := Apply(current, builtins.Registry())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// schemaPath is the checked-in file the binary embeds.
func schemaPath() string { return filepath.Join("..", "..", "pkg", "saga", "draugr.saga.schema.json") }

func TestCheckedInSchemaIsUpToDate(t *testing.T) {
	current, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	regenerated, err := Apply(current, builtins.Registry())
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(regenerated) {
		t.Error("the checked-in schema is not what the registry would generate — run `go generate ./pkg/saga/...`\n" +
			"This is the drift that let the schema fall two controls behind the registry: an editor " +
			"rejected descriptors Draugr accepted, including Draugr's own self-scan.")
	}
}

func TestSchemaListsEveryRegisteredControl(t *testing.T) {
	var doc struct {
		Defs struct {
			ControlName struct {
				AnyOf []struct {
					Const       string `json:"const"`
					Description string `json:"description"`
				} `json:"anyOf"`
			} `json:"controlName"`
		} `json:"$defs"`
	}
	data, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	inSchema := map[string]string{}
	for _, v := range doc.Defs.ControlName.AnyOf {
		inSchema[v.Const] = v.Description
	}

	registered := map[string]bool{}
	for _, c := range builtins.Registry().Controllers() {
		info := c.Info()
		registered[info.Name] = true
		desc, ok := inSchema[info.Name]
		if !ok {
			t.Errorf("control %q is registered but absent from the schema — an editor will reject "+
				"a descriptor that enables it", info.Name)
			continue
		}
		// The description an editor shows on hover has to be the one the CLI prints, or the two
		// answers to "what does this control do" drift apart.
		if desc != info.Summary {
			t.Errorf("control %q: schema says %q, the controller says %q", info.Name, desc, info.Summary)
		}
	}
	for name := range inSchema {
		if !registered[name] {
			t.Errorf("schema offers control %q, which no controller serves — autocompleting a name "+
				"that fails at scan time is worse than not offering it", name)
		}
	}
}

func TestGateControlsAutocompletes(t *testing.T) {
	// The reported symptom: IntelliSense stopped at config.gate.controls, because the key was
	// unconstrained. A threshold is only meaningful against a control that exists.
	var doc map[string]any
	data, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	defs := doc["$defs"].(map[string]any)
	gate := defs["gateConfig"].(map[string]any)["properties"].(map[string]any)
	controls := gate["controls"].(map[string]any)

	names, ok := controls["propertyNames"].(map[string]any)
	if !ok {
		t.Fatal("config.gate.controls does not constrain its keys, so an editor offers nothing")
	}
	if names["$ref"] != "#/$defs/controlName" {
		t.Errorf("propertyNames = %v, want a reference to controlName", names)
	}
}

func TestEmbeddedSchemaMatchesTheFileOnDisk(t *testing.T) {
	// The binary embeds the file; generation writes the file. If they can disagree, `draugr
	// schema` hands out something the binary does not enforce.
	data, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(saga.SchemaJSON) != string(data) {
		t.Error("the embedded schema differs from the checked-in file")
	}
}

func TestSchemaAllowsEveryEffectKind(t *testing.T) {
	// An enum written out beside the taxonomy drifts from it the moment a kind is added, and the
	// schema then rejects a value the binary accepts — an editor disagreeing with Draugr about a
	// descriptor that is valid. Same failure the generated control names exist to prevent.
	data, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	defs := doc["$defs"].(map[string]any)
	cfg := defs["config"].(map[string]any)
	props := cfg["properties"].(map[string]any)
	allow := props["allowEffects"].(map[string]any)
	items := allow["items"].(map[string]any)

	got := map[string]bool{}
	for _, v := range items["enum"].([]any) {
		got[v.(string)] = true
	}
	for _, k := range plugin.EffectKinds() {
		if !got[string(k)] {
			t.Errorf("effect %q is declarable but the schema rejects it in allowEffects", k)
		}
	}
	if len(got) != len(plugin.EffectKinds()) {
		t.Errorf("schema lists %d kinds, the taxonomy has %d", len(got), len(plugin.EffectKinds()))
	}
	// A constraint the hand-written definition carried; a generator that drops one silently is
	// worse than the drift it replaced.
	if allow["uniqueItems"] != true {
		t.Error("allowEffects no longer requires unique items")
	}
}

// The fragment schema is derived from the Saga's, so it can only be right if it is regenerated
// whenever that one changes. Drift here shows up as an editor rejecting a fragment Draugr
// accepts — the same class of problem the Saga's own guard exists to catch.
func TestCheckedInFragmentSchemaIsUpToDate(t *testing.T) {
	saga, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	regenerated, err := Apply(saga, builtins.Registry())
	if err != nil {
		t.Fatal(err)
	}
	want, err := FragmentSchema(regenerated)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(filepath.Dir(schemaPath()), "draugr.saga-fragment.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("the checked-in fragment schema is not what the generator would produce — " +
			"run `go generate ./pkg/saga/...`")
	}
}

// TestSchemaCompletesScannerBlocks is the guard behind the editor experience, which no other test
// can see: a descriptor is valid to the loader and useless to type, because the schema stops
// describing things exactly where the reader stops knowing them.
func TestSchemaCompletesScannerBlocks(t *testing.T) {
	doc := generated(t)
	defs := doc["$defs"].(map[string]any)

	sast, ok := defs["control_sast"].(map[string]any)
	if !ok {
		t.Fatal("no per-control definition for sast; an editor cannot complete inside a control")
	}
	props := sast["properties"].(map[string]any)
	for _, scanner := range []string{"semgrep", "gosec"} {
		if _, ok := props[scanner]; !ok {
			t.Errorf("sast does not name %q, so it will not be offered", scanner)
		}
	}
	if sast["additionalProperties"] != false {
		t.Error("a control that accepts any scanner key cannot flag a typo as you type")
	}

	// The option list has to come from the scanner's own schema, or what an editor offers and what
	// the engine accepts drift — and the drift surfaces as a rejected descriptor, not a warning.
	gosec := props["gosec"].(map[string]any)["properties"].(map[string]any)
	for _, opt := range []string{"enabled", "include", "exclude", "tags"} {
		if _, ok := gosec[opt]; !ok {
			t.Errorf("gosec block is missing %q", opt)
		}
	}
}

// The descriptor writes a scanner under its camelCase key. Offering the scanner's own hyphenated
// name would autocomplete something the loader then rejects, which is worse than offering nothing.
func TestSchemaUsesTheKeyADescriptorWrites(t *testing.T) {
	defs := generated(t)["$defs"].(map[string]any)
	sca := defs["control_sca"].(map[string]any)["properties"].(map[string]any)
	if _, ok := sca["trivyFs"]; !ok {
		t.Error("sca does not offer trivyFs, which is the key a descriptor writes")
	}
	if _, ok := sca["trivy-fs"]; ok {
		t.Error("sca offers the hyphenated scanner name, which the loader rejects")
	}
}

// A hand-copied list of report formats drifts, and the way drift shows up is an editor rejecting
// a descriptor Draugr accepts. `vex` reached the CLI while the schema still listed six formats.
func TestSchemaKnowsEveryReportFormat(t *testing.T) {
	defs := generated(t)["$defs"].(map[string]any)
	rc := defs["reportConfig"].(map[string]any)["properties"].(map[string]any)
	got := map[string]bool{}
	for _, v := range rc["format"].(map[string]any)["enum"].([]any) {
		got[v.(string)] = true
	}
	for _, f := range append(report.Formats(), "template") {
		if !got[f] {
			t.Errorf("the schema does not accept %q, which this build can render", f)
		}
	}
}
