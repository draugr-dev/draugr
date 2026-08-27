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

// A controller computes a scanner's configuration in Go, and Go does not produce []any.
//
// The licenses control hands trivy-license its deny and warn lists as []string, and a validator
// that recognized only the decoded shape refused them — so the most ordinary use of that control,
// naming a license the project will not accept, made the scan fail with "expected array, got
// []string" and no scanner ran at all.
func TestAnArrayIsAnArrayWhateverSliceItArrivedAs(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"additionalProperties": false,
		"properties": {
			"deny": { "type": "array", "items": { "type": "string" } }
		}
	}`)

	for name, value := range map[string]any{
		"as a descriptor decodes it": []any{"AGPL-3.0-only", "SSPL-1.0"},
		"as a controller builds it":  []string{"AGPL-3.0-only", "SSPL-1.0"},
		"empty, built in Go":         []string{},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateConfig(schema, Config{"deny": value}); err != nil {
				t.Errorf("refused a valid list: %v", err)
			}
		})
	}
}

func TestWhatIsNotAListIsStillRefused(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"deny": { "type": "array", "items": { "type": "string" } }
		}
	}`)

	for name, value := range map[string]any{
		"a bare string": "AGPL-3.0-only",
		"a number":      7,
		"a map":         map[string]any{"AGPL-3.0-only": true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateConfig(schema, Config{"deny": value}); err == nil {
				t.Error("accepted something that is not a list")
			}
		})
	}
}

// The elements are checked whichever slice carried them: a policy naming a number is a policy
// somebody mistyped, and finding out at scan time is the whole point of validating first.
func TestElementsAreCheckedInEitherShape(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"deny": { "type": "array", "items": { "type": "string" } }
		}
	}`)

	for name, value := range map[string]any{
		"decoded": []any{"AGPL-3.0-only", 7},
		"built":   []int{7},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateConfig(schema, Config{"deny": value})
			if err == nil {
				t.Fatal("accepted a list whose element is not a string")
			}
			if !strings.Contains(err.Error(), "deny[") {
				t.Errorf("error does not name the element: %v", err)
			}
		})
	}
}

// An option that accepts an identifier or that identifier written long is one rule in two shapes.
// A schema saying so has to constrain both, or the long form becomes a place unknown keys hide.
func TestValidateConfigTypeList(t *testing.T) {
	t.Parallel()

	const schema = `{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "deny": {
	      "type": "array",
	      "items": {
	        "type": ["string", "object"],
	        "additionalProperties": false,
	        "required": ["id", "reason"],
	        "properties": {
	          "id": { "type": "string" },
	          "reason": { "type": "string" }
	        }
	      }
	    }
	  }
	}`

	ok := []struct {
		name string
		cfg  Config
	}{
		{"the identifier alone", Config{"deny": []any{"AGPL-3.0-only"}}},
		{"written long", Config{"deny": []any{map[string]any{"id": "AGPL-3.0-only", "reason": "we ship binaries"}}}},
		{"both in one list", Config{"deny": []any{"SSPL-1.0", map[string]any{"id": "AGPL-3.0-only", "reason": "we ship binaries"}}}},
		{"a controller's []string", Config{"deny": []string{"AGPL-3.0-only"}}},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateConfig([]byte(schema), tc.cfg); err != nil {
				t.Errorf("rejected a valid policy: %v", err)
			}
		})
	}

	bad := []struct {
		name, want string
		cfg        Config
	}{
		{"a misspelled key in the long form", `unknown option "why"`,
			Config{"deny": []any{map[string]any{"id": "AGPL-3.0-only", "why": "we ship binaries"}}}},
		{"the long form with no reason", `missing required option "reason"`,
			Config{"deny": []any{map[string]any{"id": "AGPL-3.0-only"}}}},
		{"an identifier that is a number", "expected string or object, got integer",
			Config{"deny": []any{7}}},
		{"the list written as one value", "expected array, got string",
			Config{"deny": "AGPL-3.0-only"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig([]byte(schema), tc.cfg)
			if err == nil {
				t.Fatalf("accepted %#v", tc.cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A schema whose "type" is neither a name nor a list of them is a schema nobody can act on.
func TestValidateConfigRejectsAMalformedTypeKeyword(t *testing.T) {
	t.Parallel()

	err := ValidateConfig([]byte(`{"type": 7}`), Config{})
	if err == nil || !strings.Contains(err.Error(), "invalid config schema") {
		t.Fatalf("error = %v, want the schema itself reported", err)
	}
}

// ValidateOption judges one option without asking the rest of the schema to be satisfied — a
// control's policy is written where the scanner's other options are somebody else's to supply.
func TestValidateOption(t *testing.T) {
	t.Parallel()

	const schema = `{
	  "type": "object",
	  "required": ["productToken"],
	  "properties": {
	    "productToken": { "type": "string" },
	    "deny": { "type": "array", "items": { "type": "string" } }
	  }
	}`

	declared, err := ValidateOption([]byte(schema), "deny", []any{"AGPL-3.0-only"})
	if !declared || err != nil {
		t.Errorf("a valid option: declared=%v err=%v — required options elsewhere are not its business", declared, err)
	}
	declared, err = ValidateOption([]byte(schema), "deny", "AGPL-3.0-only")
	if !declared || err == nil || !strings.Contains(err.Error(), "expected array") {
		t.Errorf("a list written as one value: declared=%v err=%v", declared, err)
	}
	// An option this scanner has never heard of is not an error: a control served by several
	// scanners has options only some of them know, and naming one is a correct descriptor.
	if declared, err := ValidateOption([]byte(schema), "severity", "high"); declared || err != nil {
		t.Errorf("an option the schema does not declare: declared=%v err=%v", declared, err)
	}
	if declared, err := ValidateOption(nil, "deny", []any{"MIT"}); declared || err != nil {
		t.Errorf("no schema: declared=%v err=%v", declared, err)
	}
	if _, err := ValidateOption([]byte("{"), "deny", nil); err == nil {
		t.Error("a schema that is not JSON should be reported as such")
	}
}

// A mapping nested inside a typed block decodes as that block's own named map type. A check that
// recognizes only map[string]any calls it "not an object" while the descriptor is correct.
func TestValidateConfigAcceptsANamedMapType(t *testing.T) {
	t.Parallel()

	type settings map[string]any
	const schema = `{
	  "type": "object",
	  "properties": {
	    "trivyLicense": {
	      "type": "object",
	      "additionalProperties": false,
	      "properties": { "deny": { "type": "array", "items": { "type": "string" } } }
	    }
	  }
	}`

	if err := ValidateConfig([]byte(schema), Config{"trivyLicense": settings{"deny": []any{"MIT"}}}); err != nil {
		t.Errorf("rejected a nested block decoded as its own map type: %v", err)
	}
	// And it is still walked, rather than waved through for having an unfamiliar type.
	err := ValidateConfig([]byte(schema), Config{"trivyLicense": settings{"dney": []any{"MIT"}}})
	if err == nil || !strings.Contains(err.Error(), `unknown option "dney"`) {
		t.Errorf("error = %v, want the misspelled key named", err)
	}
	// An empty block is an object. A config somebody left blank is not a config of the wrong type.
	if err := ValidateConfig([]byte(schema), Config{"trivyLicense": settings(nil)}); err != nil {
		t.Errorf("rejected an empty block: %v", err)
	}
	if err := ValidateConfig([]byte(schema), Config{"trivyLicense": "deny"}); err == nil {
		t.Error("a scalar where a block belongs should be reported")
	}
}
