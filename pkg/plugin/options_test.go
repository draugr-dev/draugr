package plugin

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestOptionsReadsWhatAScannerDeclares(t *testing.T) {
	schema := json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["productToken"],
	  "properties": {
	    "project":      {"type": "string",  "description": "project name"},
	    "productToken": {"type": "string",  "description": "the product to report into"},
	    "depth":        {"type": "integer", "description": "how far back to look"},
	    "mode":         {"type": "string",  "description": "how to run", "enum": ["fast", "full"]}
	  }
	}`)
	got := Options(schema)
	if len(got) != 4 {
		t.Fatalf("got %d options, want 4: %+v", len(got), got)
	}
	// Required first, then alphabetical: what you must supply before what you may.
	want := []string{"productToken", "depth", "mode", "project"}
	for i, name := range want {
		if got[i].Name != name {
			t.Errorf("option %d = %q, want %q", i, got[i].Name, name)
		}
	}
	if !got[0].Required {
		t.Error("productToken is declared required")
	}
	if got[3].Required {
		t.Error("project is not required")
	}
	if got[1].Type != "integer" {
		t.Errorf("depth type = %q, want integer", got[1].Type)
	}
	if len(got[2].Enum) != 2 || got[2].Enum[0] != "fast" {
		t.Errorf("mode enum = %v, want [fast full]", got[2].Enum)
	}
	if got[0].Description != "the product to report into" {
		t.Errorf("description = %q", got[0].Description)
	}
}

// A scanner that accepts nothing still declares a schema. That is what makes an unknown key an
// error rather than a silent drop, so an empty option list must not be confused with an absent
// declaration. Both return no options here; the caller distinguishes them by the schema itself.
func TestOptionsIsEmptyForASchemaWithNoProperties(t *testing.T) {
	if got := Options(json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{}}`)); len(got) != 0 {
		t.Errorf("got %+v, want none", got)
	}
	if got := Options(nil); got != nil {
		t.Errorf("no schema should yield no options, got %+v", got)
	}
}

// Malformed input yields no options rather than a panic: this feeds `draugr controls` and an MCP
// tool, and neither should fail because a schema somewhere is wrong. ValidateConfig is what
// reports that, at the point it matters.
func TestOptionsToleratesAnUnparseableSchema(t *testing.T) {
	if got := Options(json.RawMessage(`{not json`)); got != nil {
		t.Errorf("got %+v, want none", got)
	}
}

// An array option constrains its elements, not itself. Reading only the property-level enum loses
// the accepted values entirely, so a caller rendering the option shows none while the validator
// still enforces them, and the two disagree in front of the user.
func TestOptionsReadsAnArrayElementEnum(t *testing.T) {
	schema := json.RawMessage(`{
	  "type": "object",
	  "properties": {
	    "pkgTypes": {
	      "type": "array",
	      "description": "which package types to analyze",
	      "items": {"type": "string", "enum": ["os", "library"]}
	    }
	  }
	}`)
	got := Options(schema)
	if len(got) != 1 {
		t.Fatalf("got %d options, want 1", len(got))
	}
	if len(got[0].Enum) != 2 || got[0].Enum[0] != "os" || got[0].Enum[1] != "library" {
		t.Errorf("enum = %v, want the element values", got[0].Enum)
	}
}

// an anyOf accepts, what each value means, and nothing a descriptor may not set.
func TestOptionsReportsWhatTheSchemaDeclares(t *testing.T) {
	schema := json.RawMessage(`{
	  "type": "object",
	  "required": ["target"],
	  "properties": {
	    "target":   {"type": "string", "description": "where to point it"},
	    "severity": {"type": "string", "enum": ["low", "high"]},
	    "tags":     {"type": "array", "items": {"enum": ["cve", "exposure"]}},
	    "mode":     {"type": "string", "anyOf": [
	                  {"const": "fast", "description": "skips the slow checks"},
	                  {"const": "full"},
	                  {"description": "a variant with no value"}]},
	    "timeout":  {"type": "string", "pattern": "^[0-9]+s$"},
	    "jobID":    {"type": "string", "readOnly": true}
	  }
	}`)
	opts := Options(schema)
	var names []string
	byName := map[string]Option{}
	for _, o := range opts {
		names = append(names, o.Name)
		byName[o.Name] = o
	}
	if want := []string{"target", "mode", "severity", "tags", "timeout"}; !slices.Equal(names, want) {
		t.Errorf("options = %v, want required first, then alphabetical, and no read-only key", names)
	}
	if o := byName["target"]; !o.Required || o.Description != "where to point it" || len(o.Schema) == 0 {
		t.Errorf("target = %+v", o)
	}
	if got := byName["severity"].Enum; !slices.Equal(got, []string{"low", "high"}) {
		t.Errorf("severity enum = %v", got)
	}
	if got := byName["tags"].Enum; !slices.Equal(got, []string{"cve", "exposure"}) {
		t.Errorf("tags enum = %v, want the items' values", got)
	}
	mode := byName["mode"]
	if !slices.Equal(mode.Enum, []string{"fast", "full"}) || mode.Meanings["fast"] != "skips the slow checks" || len(mode.Meanings) != 1 {
		t.Errorf("mode = %+v, want both consts and the one meaning given", mode)
	}
	if byName["timeout"].Pattern != "^[0-9]+s$" {
		t.Errorf("timeout pattern = %q", byName["timeout"].Pattern)
	}
	for _, empty := range []json.RawMessage{nil, json.RawMessage(`{not json`)} {
		if got := Options(empty); got != nil {
			t.Errorf("Options(%q) = %v, want nil", empty, got)
		}
	}
}
