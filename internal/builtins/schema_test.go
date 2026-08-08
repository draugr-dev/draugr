package builtins

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// TestEveryScannerDeclaresItsOptions is the guard behind "a flag either does something or says
// why it didn't", applied to descriptor options rather than command-line ones.
//
// plugin.ValidateConfig treats an absent schema as "accept anything", so a scanner without one
// takes whatever a descriptor writes under its block and drops it on the way to the argv. The
// run is green, nothing is logged, and the only symptom is a setting that had no effect. A
// scanner that genuinely accepts nothing declares that, and a descriptor assuming otherwise
// fails before the scan runs.
func TestEveryScannerDeclaresItsOptions(t *testing.T) {
	for _, s := range Registry().Scanners() {
		info := s.Info()
		if len(info.ConfigSchema) == 0 {
			t.Errorf("%s: no ConfigSchema — any option written under its block would be "+
				"accepted and then ignored; declare noScannerOptions if it takes none", info.Name)
			continue
		}
		var node struct {
			Type                 string                     `json:"type"`
			AdditionalProperties *bool                      `json:"additionalProperties"`
			Properties           map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(info.ConfigSchema, &node); err != nil {
			t.Errorf("%s: config schema is not valid JSON: %v", info.Name, err)
			continue
		}
		if node.Type != "object" {
			t.Errorf("%s: config schema type = %q, want object", info.Name, node.Type)
		}
		// Without this, an unknown key falls through validation and the schema documents the
		// options without enforcing them — which is the same silent drop, one level down.
		if node.AdditionalProperties == nil || *node.AdditionalProperties {
			t.Errorf("%s: config schema must set additionalProperties:false, or a mistyped "+
				"option is accepted and ignored", info.Name)
		}
		for opt, raw := range node.Properties {
			var prop struct {
				Description string `json:"description"`
			}
			_ = json.Unmarshal(raw, &prop)
			// An option nobody can find is an option nobody uses. `draugr controls --options`
			// prints these, and a blank one prints a blank line.
			if strings.TrimSpace(prop.Description) == "" {
				t.Errorf("%s: option %q has no description", info.Name, opt)
			}
		}
	}
}

// TestDeclaredOptionsRejectAnUnknownKey proves the declaration is load-bearing rather than
// documentation: the same validator the engine runs must refuse a key no scanner reads.
func TestDeclaredOptionsRejectAnUnknownKey(t *testing.T) {
	for _, s := range Registry().Scanners() {
		info := s.Info()
		err := plugin.ValidateConfig(info.ConfigSchema, plugin.Config{"noSuchOption": "x"})
		if err == nil {
			t.Errorf("%s: an unknown option was accepted", info.Name)
			continue
		}
		if !strings.Contains(err.Error(), "noSuchOption") {
			t.Errorf("%s: error should name the offending option, got %q", info.Name, err)
		}
	}
}
