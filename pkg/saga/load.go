package saga

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// envPattern matches ${{ VAR_NAME }} with optional surrounding whitespace.
var envPattern = regexp.MustCompile(`\$\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// Load parses a Saga descriptor from YAML bytes, substituting ${{ VAR }} references from
// the environment and validating the result.
func Load(data []byte) (*Model, error) {
	expanded, err := expandEnv(data)
	if err != nil {
		return nil, err
	}

	var m Model
	if err := yaml.Unmarshal(expanded, &m); err != nil {
		return nil, fmt.Errorf("parse saga: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// LoadFile reads and parses a Saga descriptor from a file path.
func LoadFile(path string) (*Model, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-provided by design
	if err != nil {
		return nil, fmt.Errorf("read saga %q: %w", path, err)
	}
	return Load(data)
}

// expandEnv replaces every ${{ VAR }} with the value of the VAR environment variable.
// It returns an error listing any referenced variables that are not set, so config
// mistakes fail fast instead of silently producing empty values.
func expandEnv(data []byte) ([]byte, error) {
	var missing []string
	seen := map[string]bool{}

	out := envPattern.ReplaceAllStringFunc(string(data), func(match string) string {
		name := envPattern.FindStringSubmatch(match)[1]
		val, ok := os.LookupEnv(name)
		if !ok {
			if !seen[name] {
				seen[name] = true
				missing = append(missing, name)
			}
			return match
		}
		return val
	})

	if len(missing) > 0 {
		return nil, fmt.Errorf("undefined environment variable(s) referenced in saga: %s",
			strings.Join(missing, ", "))
	}
	return []byte(out), nil
}
