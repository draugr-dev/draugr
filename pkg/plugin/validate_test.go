package plugin

import (
	"encoding/json"
	"strings"
	"testing"
)

const objSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "config":   { "type": "string" },
    "severity": { "type": "string", "enum": ["low", "medium", "high"] },
    "limit":    { "type": "integer" },
    "ratio":    { "type": "number" },
    "on":       { "type": "boolean" },
    "tags":     { "type": "array", "items": { "type": "string" } }
  }
}`

func TestValidateConfigEmptySchema(t *testing.T) {
	if err := ValidateConfig(nil, Config{"anything": 1}); err != nil {
		t.Errorf("empty schema should accept anything: %v", err)
	}
}

func TestValidateConfigValid(t *testing.T) {
	cfg := Config{
		"config":   "p/ci",
		"severity": "high",
		"limit":    5,
		"ratio":    0.5,
		"on":       true,
		"tags":     []any{"cve", "exposure"},
	}
	if err := ValidateConfig(json.RawMessage(objSchema), cfg); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestValidateConfigUnknownKey(t *testing.T) {
	err := ValidateConfig(json.RawMessage(objSchema), Config{"cnofig": "typo"})
	if err == nil || !strings.Contains(err.Error(), `unknown option "cnofig"`) {
		t.Errorf("want unknown-option error, got %v", err)
	}
}

func TestValidateConfigWrongType(t *testing.T) {
	err := ValidateConfig(json.RawMessage(objSchema), Config{"config": true})
	if err == nil || !strings.Contains(err.Error(), "expected string, got boolean") {
		t.Errorf("want type error, got %v", err)
	}
}

func TestValidateConfigEnum(t *testing.T) {
	err := ValidateConfig(json.RawMessage(objSchema), Config{"severity": "critical"})
	if err == nil || !strings.Contains(err.Error(), "must be one of") {
		t.Errorf("want enum error, got %v", err)
	}
}

func TestValidateConfigArrayItemType(t *testing.T) {
	err := ValidateConfig(json.RawMessage(objSchema), Config{"tags": []any{"ok", 3}})
	if err == nil || !strings.Contains(err.Error(), "tags[1]") {
		t.Errorf("want array-item error, got %v", err)
	}
}

func TestValidateConfigInteger(t *testing.T) {
	if err := ValidateConfig(json.RawMessage(objSchema), Config{"limit": 3}); err != nil {
		t.Errorf("int should satisfy integer: %v", err)
	}
	err := ValidateConfig(json.RawMessage(objSchema), Config{"limit": "3"})
	if err == nil || !strings.Contains(err.Error(), "expected integer") {
		t.Errorf("want integer type error, got %v", err)
	}
}

func TestValidateConfigNumberAcceptsInt(t *testing.T) {
	if err := ValidateConfig(json.RawMessage(objSchema), Config{"ratio": 2}); err != nil {
		t.Errorf("integer should satisfy number: %v", err)
	}
}

func TestValidateConfigRequired(t *testing.T) {
	schema := `{"type":"object","required":["config"],"properties":{"config":{"type":"string"}}}`
	err := ValidateConfig(json.RawMessage(schema), Config{})
	if err == nil || !strings.Contains(err.Error(), `missing required option "config"`) {
		t.Errorf("want required error, got %v", err)
	}
}

func TestValidateConfigNestedObject(t *testing.T) {
	schema := `{
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "auth": {
          "type": "object",
          "additionalProperties": false,
          "properties": { "user": { "type": "string" } }
        }
      }
    }`
	if err := ValidateConfig(json.RawMessage(schema), Config{"auth": map[string]any{"user": "x"}}); err != nil {
		t.Errorf("valid nested object rejected: %v", err)
	}
	err := ValidateConfig(json.RawMessage(schema), Config{"auth": map[string]any{"role": "x"}})
	if err == nil || !strings.Contains(err.Error(), `option "auth": unknown option "role"`) {
		t.Errorf("want nested unknown-option error, got %v", err)
	}
}

func TestValidateConfigAdditionalPropsAllowed(t *testing.T) {
	// additionalProperties absent → extra keys allowed.
	schema := `{"type":"object","properties":{"config":{"type":"string"}}}`
	if err := ValidateConfig(json.RawMessage(schema), Config{"config": "x", "extra": 1}); err != nil {
		t.Errorf("extra key should be allowed without additionalProperties:false: %v", err)
	}
}

func TestValidateConfigInvalidSchema(t *testing.T) {
	err := ValidateConfig(json.RawMessage(`{not json`), Config{})
	if err == nil || !strings.Contains(err.Error(), "invalid config schema") {
		t.Errorf("want schema-parse error, got %v", err)
	}
}

func TestValidateConfigRootTypeMismatchIsObject(t *testing.T) {
	// Root is always an object (Config); a non-object property value is caught per-option.
	schema := `{"type":"object","properties":{"n":{"type":"integer"}}}`
	if err := ValidateConfig(json.RawMessage(schema), Config{"n": 1}); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}
