package plugin

import (
	"encoding/json"
	"slices"
	"testing"
)

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
