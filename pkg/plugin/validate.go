package plugin

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// ValidateConfig checks cfg against a scanner's declared JSON Schema (ScannerInfo.ConfigSchema).
// An empty schema accepts any config. Validation is fail-fast: the first violation is returned
// as a human-readable error naming the offending option, so a mistyped Saga key or wrong value
// type is reported before any scan runs.
//
// It supports the subset of JSON Schema Draugr emits for scanner config: object schemas with
// "properties", "required", and "additionalProperties"; and scalar/array leaves with "type"
// (string, boolean, integer, number, array, object) and "enum". This is deliberately narrow —
// scanner schemas are authored in-repo (a typed allowlist of options), not accepted from users —
// while remaining valid JSON Schema that external tooling and the config wizard can consume.
func ValidateConfig(schema json.RawMessage, cfg Config) error {
	if len(schema) == 0 {
		return nil
	}
	var node schemaNode
	if err := json.Unmarshal(schema, &node); err != nil {
		return fmt.Errorf("invalid config schema: %w", err)
	}
	return validateValue(node, map[string]any(cfg), "")
}

// schemaNode is the supported subset of a JSON Schema node.
type schemaNode struct {
	Type                 string                `json:"type"`
	Properties           map[string]schemaNode `json:"properties"`
	Required             []string              `json:"required"`
	Enum                 []any                 `json:"enum"`
	Items                *schemaNode           `json:"items"`
	AdditionalProperties *bool                 `json:"additionalProperties"`
}

func validateValue(node schemaNode, val any, path string) error {
	if node.Type != "" {
		if err := checkType(node.Type, val, path); err != nil {
			return err
		}
	}
	if len(node.Enum) > 0 && !enumContains(node.Enum, val) {
		return fmt.Errorf("%s: must be one of %s", optionLabel(path), formatEnum(node.Enum))
	}

	switch node.Type {
	case "object":
		m := val.(map[string]any) // safe: checkType passed
		if node.AdditionalProperties != nil && !*node.AdditionalProperties {
			for _, k := range sortedKeys(m) {
				if _, known := node.Properties[k]; !known {
					return fmt.Errorf("%s: unknown option %q", optionLabel(path), k)
				}
			}
		}
		for _, req := range node.Required {
			if _, ok := m[req]; !ok {
				return fmt.Errorf("%s: missing required option %q", optionLabel(path), req)
			}
		}
		for _, k := range sortedKeys(m) {
			sub, ok := node.Properties[k]
			if !ok {
				continue // unknown keys already rejected above when additionalProperties is false
			}
			if err := validateValue(sub, m[k], joinPath(path, k)); err != nil {
				return err
			}
		}
	case "array":
		if node.Items != nil {
			for i, item := range val.([]any) { // safe: checkType passed
				if err := validateValue(*node.Items, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkType reports whether val matches a JSON Schema type, mapping the Go types produced by
// YAML/JSON decoding of a Saga (string, bool, int/float, []any, map[string]any).
func checkType(typ string, val any, path string) error {
	ok := false
	switch typ {
	case "string":
		_, ok = val.(string)
	case "boolean":
		_, ok = val.(bool)
	case "integer":
		ok = isInteger(val)
	case "number":
		ok = isInteger(val) || isFloat(val)
	case "array":
		_, ok = val.([]any)
	case "object":
		_, ok = val.(map[string]any)
	default:
		return nil // unsupported type keyword: don't constrain
	}
	if !ok {
		return fmt.Errorf("%s: expected %s, got %s", optionLabel(path), typ, jsonType(val))
	}
	return nil
}

func isInteger(v any) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}

func isFloat(v any) bool {
	switch v.(type) {
	case float32, float64:
		return true
	default:
		return false
	}
}

// jsonType names a decoded value's type for error messages.
func jsonType(v any) string {
	switch {
	case v == nil:
		return "null"
	case isInteger(v):
		return "integer"
	case isFloat(v):
		return "number"
	}
	switch v.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return reflect.TypeOf(v).String()
	}
}

func enumContains(enum []any, val any) bool {
	for _, e := range enum {
		if reflect.DeepEqual(e, val) {
			return true
		}
	}
	return false
}

func formatEnum(enum []any) string {
	parts := make([]string, len(enum))
	for i, e := range enum {
		parts[i] = fmt.Sprintf("%v", e)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// optionLabel names the thing an error is about: a specific option, or "config" at the root.
func optionLabel(path string) string {
	if path == "" {
		return "config"
	}
	return fmt.Sprintf("option %q", path)
}
