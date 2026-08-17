package plugin

import (
	"encoding/json"
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

// A scanner that accepts nothing still declares a schema — that is what makes an unknown key an
// error rather than a silent drop — so an empty option list must not be confused with an absent
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
// the accepted values entirely — so a caller rendering the option shows none while the validator
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
